package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/crypto/bcrypt"
)

var (
	usersBucket = []byte("users")
	bcryptCost  = 12
)

type User struct {
	Username     string    `json:"username"`
	PasswordHash string    `json:"password_hash"`
	CreatedAt    time.Time `json:"created_at"`
	LastLogin    time.Time `json:"last_login"`
	ChrootDir    string    `json:"chroot_dir"`
	HomeDir      string    `json:"home_dir"`
	UID          int       `json:"uid"`
	IP           string    `json:"ip"`
	VethName     string    `json:"veth_name"`
}

type Store struct {
	db *bolt.DB
}

func NewStore(dbPath string) (*Store, error) {
	db, err := bolt.Open(dbPath, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Create buckets
	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(usersBucket)
		return err
	})
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create bucket: %w", err)
	}

	return &Store{db: db}, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) CreateUser(username, password string, uid int) error {
	if len(password) < 6 {
		return fmt.Errorf("password must be at least 6 characters")
	}

	passwordHash := hashPassword(password)

	user := &User{
		Username:     username,
		PasswordHash: passwordHash,
		CreatedAt:    time.Now(),
		LastLogin:    time.Now(),
		UID:          uid,
	}

	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(usersBucket)
		
		// Check if user exists
		if b.Get([]byte(username)) != nil {
			return fmt.Errorf("user already exists")
		}

		data, err := json.Marshal(user)
		if err != nil {
			return err
		}

		return b.Put([]byte(username), data)
	})
}

func (s *Store) GetUser(username string) (*User, error) {
	var user User

	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(usersBucket)
		data := b.Get([]byte(username))
		
		if data == nil {
			return fmt.Errorf("user not found")
		}

		return json.Unmarshal(data, &user)
	})

	return &user, err
}

func (s *Store) UpdateUser(user *User) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(usersBucket)
		
		data, err := json.Marshal(user)
		if err != nil {
			return err
		}

		return b.Put([]byte(user.Username), data)
	})
}

func (s *Store) VerifyPassword(username, password string) (*User, error) {
	user, err := s.GetUser(username)
	if err != nil {
		return nil, err
	}

	// Try bcrypt first (new hash format)
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	if err == nil {
		// Password is correct, update last login
		user.LastLogin = time.Now()
		s.UpdateUser(user)
		return user, nil
	}

	// If bcrypt fails, check if it's a legacy SHA256 hash (64 hex chars)
	if len(user.PasswordHash) == 64 && isHexString(user.PasswordHash) {
		legacyHash := hashPasswordLegacy(password)
		if user.PasswordHash == legacyHash {
			// Legacy password is correct, rehash with bcrypt
			log.Info().Str("username", username).Msg("Migrating user password to bcrypt")
			newHash := hashPassword(password)
			user.PasswordHash = newHash
			user.LastLogin = time.Now()
			s.UpdateUser(user)
			return user, nil
		}
	}

	return nil, fmt.Errorf("invalid password")
}

func (s *Store) ListUsers() ([]*User, error) {
	var users []*User

	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(usersBucket)
		
		return b.ForEach(func(k, v []byte) error {
			var user User
			if err := json.Unmarshal(v, &user); err != nil {
				return err
			}
			users = append(users, &user)
			return nil
		})
	})

	return users, err
}

func (s *Store) DeleteUser(username string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(usersBucket)
		return b.Delete([]byte(username))
	})
}

func hashPassword(password string) string {
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		// This should rarely happen, but fallback to legacy if it does
		log.Warn().Err(err).Msg("Failed to generate bcrypt hash, falling back to SHA256")
		return hashPasswordLegacy(password)
	}
	return string(hashedBytes)
}

// hashPasswordLegacy is the old SHA256 implementation for migration
func hashPasswordLegacy(password string) string {
	hash := sha256.Sum256([]byte(password))
	return hex.EncodeToString(hash[:])
}

// isHexString checks if a string contains only hex characters
func isHexString(s string) bool {
	for _, c := range strings.ToLower(s) {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}
