package s3

import (
	"bytes"
	"strings"
	"sync"

	"github.com/moomerman/go-lib/kvstore"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
)

// Store implements kvstore.Store using S3.
type Store struct {
	Endpoint    string
	AccessToken string
	SecretToken string
	Bucket      string
	Region      string

	sessionMu sync.Mutex
	session   *session.Session // initialized by s3Session()
}

// Get implements kvstore.Store.Get
func (s *Store) Get(key string) ([]byte, error) {

	session, err := s.s3Session()
	if err != nil {
		return nil, err
	}

	downloader := s3manager.NewDownloader(session)

	buff := &aws.WriteAtBuffer{}

	_, err = downloader.Download(buff,
		&s3.GetObjectInput{
			Bucket: aws.String(s.Bucket),
			Key:    aws.String(key),
		})
	if err != nil {
		if strings.HasPrefix(err.Error(), s3.ErrCodeNoSuchKey) {
			return nil, kvstore.ErrCacheMiss
		}
		return nil, err
	}

	return buff.Bytes(), nil
}

// Put implements kvstore.Store.Put
func (s *Store) Put(key string, data []byte) error {

	session, err := s.s3Session()
	if err != nil {
		return err
	}

	uploader := s3manager.NewUploader(session)

	_, err = uploader.Upload(&s3manager.UploadInput{
		Bucket: aws.String(s.Bucket),
		Key:    aws.String(key),
		Body:   bytes.NewBuffer(data),
	})
	if err != nil {
		return err
	}

	return nil
}

// Delete implements kvstore.Store.Delete
func (s *Store) Delete(key string) error {
	svc := s3.New(s.session)

	_, err := svc.DeleteObject(&s3.DeleteObjectInput{
		Bucket: aws.String(s.Bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return err
	}

	err = svc.WaitUntilObjectNotExists(&s3.HeadObjectInput{
		Bucket: aws.String(s.Bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return err
	}

	return nil
}

func (s *Store) s3Session() (*session.Session, error) {
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()

	if s.session != nil {
		return s.session, nil
	}

	creds := credentials.NewStaticCredentials(
		s.AccessToken,
		s.SecretToken,
		"",
	)

	session, err := session.NewSession(&aws.Config{
		Endpoint:         aws.String(s.Endpoint),
		Region:           aws.String(s.Region),
		S3ForcePathStyle: aws.Bool(true),
		Credentials:      creds,
	})
	if err != nil {
		return nil, err
	}

	s.session = session
	return session, nil
}
