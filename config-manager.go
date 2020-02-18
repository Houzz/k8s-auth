package main

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
)

// Options provides the means to control what configuration value will be loaded
type Options struct {
	profile string
}

// ConfigManager provides methods to load configurations
type ConfigManager interface {
	get(store string, key string) ([]byte, error)
}

// NewConfigManager functions as the factory of interface ConfigManager
func NewConfigManager(o *Options) ConfigManager {
	return newS3ConfigManager(o)
}

type s3ConfigManager struct {
	session      *session.Session
	s3Downloader *s3manager.Downloader
}

func newS3ConfigManager(o *Options) s3ConfigManager {
	cm := s3ConfigManager{}
	cm.session = session.Must(session.NewSessionWithOptions(
		session.Options{
			Profile:           o.profile,
			SharedConfigState: session.SharedConfigEnable,
		}))
	cm.s3Downloader = s3manager.NewDownloader(cm.session)

	return cm
}

func (cm s3ConfigManager) get(store string, key string) ([]byte, error) {
	if store == "" {
		store = S3Bucket
	}
	if key == "" {
		key = S3Key
	}
	buff := &aws.WriteAtBuffer{}
	if _, err := cm.s3Downloader.Download(
		buff,
		&s3.GetObjectInput{
			Bucket: aws.String(store),
			Key:    aws.String(key),
		}); err != nil {
		return nil, fmt.Errorf("Failed to download from s3://%s/%s", store, key)
	}
	return buff.Bytes(), nil
}
