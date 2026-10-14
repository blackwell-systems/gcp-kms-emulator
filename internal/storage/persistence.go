// persistence.go lets the emulator keep its state on disk, so key material
// survives a restart. It is opt-in: without EnablePersistence the storage
// stays purely in-memory.
//
// The whole state is rewritten after every successful mutation. The file is
// replaced atomically (write to a temp file, then rename), so a crash leaves
// either the previous state or the new one, never a partial file.
//
// The state file holds private key material in plaintext. It is created with
// 0600 permissions and must only ever contain development keys.
package storage

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"

	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// StateFileName is the name of the file the state is kept in, inside the data directory.
const StateFileName = "state.json"

// snapshotFormatVersion is bumped whenever the on-disk layout changes incompatibly.
const snapshotFormatVersion = 1

type snapshot struct {
	FormatVersion int               `json:"formatVersion"`
	KeyRings      []snapshotKeyRing `json:"keyRings"`
}

type snapshotKeyRing struct {
	Name       string              `json:"name"`
	CreateTime time.Time           `json:"createTime"`
	CryptoKeys []snapshotCryptoKey `json:"cryptoKeys"`
	ImportJobs []snapshotImportJob `json:"importJobs"`
}

type snapshotCryptoKey struct {
	Name                            string                           `json:"name"`
	CreateTime                      time.Time                        `json:"createTime"`
	Purpose                         kmspb.CryptoKey_CryptoKeyPurpose `json:"purpose"`
	PrimaryVersion                  string                           `json:"primaryVersion"`
	NextVersionID                   int64                            `json:"nextVersionId"`
	VersionTemplate                 json.RawMessage                  `json:"versionTemplate,omitempty"`
	Labels                          map[string]string                `json:"labels,omitempty"`
	RotationPeriod                  *time.Duration                   `json:"rotationPeriod,omitempty"`
	NextRotationTime                *time.Time                       `json:"nextRotationTime,omitempty"`
	DestroyScheduledDuration        *time.Duration                   `json:"destroyScheduledDuration,omitempty"`
	DestroyScheduledDurationDefault *time.Duration                   `json:"destroyScheduledDurationDefault,omitempty"`
	Versions                        []snapshotCryptoKeyVersion       `json:"versions"`
}

type snapshotCryptoKeyVersion struct {
	Name          string                                           `json:"name"`
	State         kmspb.CryptoKeyVersion_CryptoKeyVersionState     `json:"state"`
	CreateTime    time.Time                                        `json:"createTime"`
	Algorithm     kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm `json:"algorithm"`
	SymmetricKey  []byte                                           `json:"symmetricKey,omitempty"`
	PrivateKeyDER []byte                                           `json:"privateKeyDer,omitempty"`
	PublicKeyPEM  string                                           `json:"publicKeyPem,omitempty"`
	HMACKey       []byte                                           `json:"hmacKey,omitempty"`
	DestroyTime   time.Time                                        `json:"destroyTime,omitzero"`
}

type snapshotImportJob struct {
	Name            string                         `json:"name"`
	State           kmspb.ImportJob_ImportJobState `json:"state"`
	ImportMethod    kmspb.ImportJob_ImportMethod   `json:"importMethod"`
	ProtectionLevel kmspb.ProtectionLevel          `json:"protectionLevel"`
	CreateTime      time.Time                      `json:"createTime"`
	ExpireTime      time.Time                      `json:"expireTime"`
	PublicKeyPEM    string                         `json:"publicKeyPem"`
	PrivateKeyDER   []byte                         `json:"privateKeyDer"`
}

// EnablePersistence restores the state saved in dataDir, if there is any, and
// saves every later change back to it. The directory is created if missing.
// The state is written once before returning, so an unwritable directory is
// reported at startup rather than on the first mutation.
func (s *Storage) EnablePersistence(dataDir string) error {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return fmt.Errorf("create data directory: %w", err)
	}

	path := filepath.Join(dataDir, StateFileName)

	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return fmt.Errorf("read state file: %w", err)
	default:
		keyrings, err := decodeSnapshot(data)
		if err != nil {
			return fmt.Errorf("restore state from %s: %w", path, err)
		}
		s.keyrings = keyrings
	}

	s.persistPath = path
	return s.persistLocked()
}

// persistLocked writes the current state to disk. Callers must hold s.mu.
// It is a no-op when persistence is disabled.
func (s *Storage) persistLocked() error {
	if s.persistPath == "" {
		return nil
	}

	data, err := encodeSnapshot(s.keyrings)
	if err != nil {
		return fmt.Errorf("encode state: %w", err)
	}

	if err := writeFileAtomically(s.persistPath, data); err != nil {
		return fmt.Errorf("persist state: %w", err)
	}
	return nil
}

func writeFileAtomically(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func encodeSnapshot(keyrings map[string]*StoredKeyRing) ([]byte, error) {
	snap := snapshot{FormatVersion: snapshotFormatVersion, KeyRings: []snapshotKeyRing{}}

	for _, keyring := range keyrings {
		snapKeyRing := snapshotKeyRing{
			Name:       keyring.Name,
			CreateTime: keyring.CreateTime,
			CryptoKeys: []snapshotCryptoKey{},
			ImportJobs: []snapshotImportJob{},
		}

		for _, cryptoKey := range keyring.CryptoKeys {
			snapKey, err := encodeCryptoKey(cryptoKey)
			if err != nil {
				return nil, err
			}
			snapKeyRing.CryptoKeys = append(snapKeyRing.CryptoKeys, snapKey)
		}
		sort.Slice(snapKeyRing.CryptoKeys, func(i, j int) bool { return snapKeyRing.CryptoKeys[i].Name < snapKeyRing.CryptoKeys[j].Name })

		for _, importJob := range keyring.ImportJobs {
			snapJob, err := encodeImportJob(importJob)
			if err != nil {
				return nil, err
			}
			snapKeyRing.ImportJobs = append(snapKeyRing.ImportJobs, snapJob)
		}
		sort.Slice(snapKeyRing.ImportJobs, func(i, j int) bool { return snapKeyRing.ImportJobs[i].Name < snapKeyRing.ImportJobs[j].Name })

		snap.KeyRings = append(snap.KeyRings, snapKeyRing)
	}
	sort.Slice(snap.KeyRings, func(i, j int) bool { return snap.KeyRings[i].Name < snap.KeyRings[j].Name })

	return json.MarshalIndent(snap, "", "  ")
}

func encodeCryptoKey(cryptoKey *StoredCryptoKey) (snapshotCryptoKey, error) {
	snapKey := snapshotCryptoKey{
		Name:                            cryptoKey.Name,
		CreateTime:                      cryptoKey.CreateTime,
		Purpose:                         cryptoKey.Purpose,
		PrimaryVersion:                  cryptoKey.PrimaryVersion,
		NextVersionID:                   cryptoKey.NextVersionID,
		Labels:                          cryptoKey.Labels,
		RotationPeriod:                  durationToSnapshot(cryptoKey.RotationPeriod),
		NextRotationTime:                timestampToSnapshot(cryptoKey.NextRotationTime),
		DestroyScheduledDuration:        durationToSnapshot(cryptoKey.DestroyScheduledDuration),
		DestroyScheduledDurationDefault: durationToSnapshot(cryptoKey.DestroyScheduledDurationDefault),
		Versions:                        []snapshotCryptoKeyVersion{},
	}

	if cryptoKey.VersionTemplate != nil {
		template, err := protojson.Marshal(cryptoKey.VersionTemplate)
		if err != nil {
			return snapshotCryptoKey{}, fmt.Errorf("encode version template of %s: %w", cryptoKey.Name, err)
		}
		snapKey.VersionTemplate = template
	}

	for _, version := range cryptoKey.Versions {
		snapVersion := snapshotCryptoKeyVersion{
			Name:         version.Name,
			State:        version.State,
			CreateTime:   version.CreateTime,
			Algorithm:    version.Algorithm,
			SymmetricKey: version.SymmetricKey,
			HMACKey:      version.HMACKey,
			DestroyTime:  version.DestroyTime,
		}
		if version.AsymmetricKey != nil {
			snapVersion.PrivateKeyDER = version.AsymmetricKey.PrivateKeyDER
			snapVersion.PublicKeyPEM = version.AsymmetricKey.PublicKeyPEM
		}
		snapKey.Versions = append(snapKey.Versions, snapVersion)
	}
	sort.Slice(snapKey.Versions, func(i, j int) bool { return snapKey.Versions[i].Name < snapKey.Versions[j].Name })

	return snapKey, nil
}

func encodeImportJob(importJob *StoredImportJob) (snapshotImportJob, error) {
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(importJob.PrivateKey)
	if err != nil {
		return snapshotImportJob{}, fmt.Errorf("encode wrapping key of %s: %w", importJob.Name, err)
	}

	return snapshotImportJob{
		Name:            importJob.Name,
		State:           importJob.State,
		ImportMethod:    importJob.ImportMethod,
		ProtectionLevel: importJob.ProtectionLevel,
		CreateTime:      importJob.CreateTime,
		ExpireTime:      importJob.ExpireTime,
		PublicKeyPEM:    importJob.PublicKeyPEM,
		PrivateKeyDER:   privateKeyDER,
	}, nil
}

func decodeSnapshot(data []byte) (map[string]*StoredKeyRing, error) {
	var snap snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("decode state: %w", err)
	}
	if snap.FormatVersion != snapshotFormatVersion {
		return nil, fmt.Errorf("unsupported state format version %d (expected %d)", snap.FormatVersion, snapshotFormatVersion)
	}

	keyrings := make(map[string]*StoredKeyRing, len(snap.KeyRings))
	for _, snapKeyRing := range snap.KeyRings {
		keyring := &StoredKeyRing{
			Name:       snapKeyRing.Name,
			CreateTime: snapKeyRing.CreateTime,
			CryptoKeys: make(map[string]*StoredCryptoKey, len(snapKeyRing.CryptoKeys)),
			ImportJobs: make(map[string]*StoredImportJob, len(snapKeyRing.ImportJobs)),
		}

		for _, snapKey := range snapKeyRing.CryptoKeys {
			cryptoKey, err := decodeCryptoKey(snapKey)
			if err != nil {
				return nil, err
			}
			keyring.CryptoKeys[cryptoKey.Name] = cryptoKey
		}

		for _, snapJob := range snapKeyRing.ImportJobs {
			importJob, err := decodeImportJob(snapJob)
			if err != nil {
				return nil, err
			}
			keyring.ImportJobs[importJob.Name] = importJob
		}

		keyrings[keyring.Name] = keyring
	}

	return keyrings, nil
}

func decodeCryptoKey(snapKey snapshotCryptoKey) (*StoredCryptoKey, error) {
	cryptoKey := &StoredCryptoKey{
		Name:                            snapKey.Name,
		CreateTime:                      snapKey.CreateTime,
		Purpose:                         snapKey.Purpose,
		PrimaryVersion:                  snapKey.PrimaryVersion,
		NextVersionID:                   snapKey.NextVersionID,
		Labels:                          snapKey.Labels,
		RotationPeriod:                  durationFromSnapshot(snapKey.RotationPeriod),
		NextRotationTime:                timestampFromSnapshot(snapKey.NextRotationTime),
		DestroyScheduledDuration:        durationFromSnapshot(snapKey.DestroyScheduledDuration),
		DestroyScheduledDurationDefault: durationFromSnapshot(snapKey.DestroyScheduledDurationDefault),
		Versions:                        make(map[string]*StoredCryptoKeyVersion, len(snapKey.Versions)),
	}

	if len(snapKey.VersionTemplate) > 0 {
		template := &kmspb.CryptoKeyVersionTemplate{}
		if err := protojson.Unmarshal(snapKey.VersionTemplate, template); err != nil {
			return nil, fmt.Errorf("decode version template of %s: %w", snapKey.Name, err)
		}
		cryptoKey.VersionTemplate = template
	}

	for _, snapVersion := range snapKey.Versions {
		version := &StoredCryptoKeyVersion{
			Name:         snapVersion.Name,
			State:        snapVersion.State,
			CreateTime:   snapVersion.CreateTime,
			Algorithm:    snapVersion.Algorithm,
			SymmetricKey: snapVersion.SymmetricKey,
			HMACKey:      snapVersion.HMACKey,
			DestroyTime:  snapVersion.DestroyTime,
		}
		if len(snapVersion.PrivateKeyDER) > 0 {
			version.AsymmetricKey = &AsymmetricKeyMaterial{
				PrivateKeyDER: snapVersion.PrivateKeyDER,
				PublicKeyPEM:  snapVersion.PublicKeyPEM,
			}
		}
		cryptoKey.Versions[version.Name] = version
	}

	return cryptoKey, nil
}

func decodeImportJob(snapJob snapshotImportJob) (*StoredImportJob, error) {
	parsed, err := x509.ParsePKCS8PrivateKey(snapJob.PrivateKeyDER)
	if err != nil {
		return nil, fmt.Errorf("decode wrapping key of %s: %w", snapJob.Name, err)
	}
	privateKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("decode wrapping key of %s: expected an RSA key, got %T", snapJob.Name, parsed)
	}

	return &StoredImportJob{
		Name:            snapJob.Name,
		State:           snapJob.State,
		ImportMethod:    snapJob.ImportMethod,
		ProtectionLevel: snapJob.ProtectionLevel,
		CreateTime:      snapJob.CreateTime,
		ExpireTime:      snapJob.ExpireTime,
		PublicKeyPEM:    snapJob.PublicKeyPEM,
		PrivateKey:      privateKey,
	}, nil
}

func durationToSnapshot(d *durationpb.Duration) *time.Duration {
	if d == nil {
		return nil
	}
	value := d.AsDuration()
	return &value
}

func durationFromSnapshot(d *time.Duration) *durationpb.Duration {
	if d == nil {
		return nil
	}
	return durationpb.New(*d)
}

func timestampToSnapshot(t *timestamppb.Timestamp) *time.Time {
	if t == nil {
		return nil
	}
	value := t.AsTime()
	return &value
}

func timestampFromSnapshot(t *time.Time) *timestamppb.Timestamp {
	if t == nil {
		return nil
	}
	return timestamppb.New(*t)
}
