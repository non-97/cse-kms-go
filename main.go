package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/aws/amazon-s3-encryption-client-go/v3/client"
	"github.com/aws/amazon-s3-encryption-client-go/v3/materials"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func main() {
	var (
		download   = flag.Bool("download", false, "Download S3 objects to local with CSE-KMS")
		upload     = flag.Bool("upload", false, "Upload local file to S3 bucket with CSE-KMS")
		bucketName = flag.String("bucket", "", "S3 bucket name")
		objectKey  = flag.String("object-key", "", "S3 object key")
		localPath  = flag.String("path", "", "Local path")
		kmsKeyArn  = flag.String("kms-key-arn", "", "KMS key ARN")
	)
	flag.Parse()

	// download と upload の両方またはどちらも設定されていない場合は終了
	if (*download && *upload) || (!*download && !*upload) {
		log.Fatalf("Error : download か upload のいずれか一方を指定してください")
	}

	// AWSの認証情報を読み込み
	// MFAのコード入力を標準入力で受け付ける
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx, config.WithAssumeRoleCredentialOptions(func(options *stscreds.AssumeRoleOptions) {
		options.TokenProvider = func() (string, error) {
			return stscreds.StdinTokenProvider()
		}
	}))
	if err != nil {
		log.Fatalf("unable to load AWS credential:, %v", err)
	}

	// AWS SDK client
	s3Client := s3.NewFromConfig(cfg)
	kmsClient := kms.NewFromConfig(cfg)

	// keyring と CMM の作成
	cmm, err := materials.NewCryptographicMaterialsManager(materials.NewKmsKeyring(kmsClient, *kmsKeyArn, func(options *materials.KeyringOptions) {
		options.EnableLegacyWrappingAlgorithms = false
	}))
	if err != nil {
		log.Fatalf("error while creating new CMM")
	}

	// Amazon S3 Encryption Client
	s3EncryptionClient, err := client.New(s3Client, cmm, func(clientOptions *client.EncryptionClientOptions) {
		clientOptions.EnableLegacyUnauthenticatedModes = false
	})
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}

	// オブジェクトをGetする場合
	if *download {
		if err := GetObjectsWithCseKms(ctx, s3EncryptionClient, s3Client, *localPath, *bucketName, *objectKey, cmm); err != nil {
			log.Fatalf("Failed to download objects: %v", err)
		}
	}

	// オブジェクトをPutする場合
	if *upload {
		if err := PutObjectsWithCseKms(ctx, s3EncryptionClient, s3Client, *localPath, *bucketName, *objectKey, cmm); err != nil {
			log.Fatalf("Failed to upload objects: %v", err)
		}
	}
}

func GetObjectsWithCseKms(ctx context.Context, s3EncryptionClient *client.S3EncryptionClientV3, s3Client *s3.Client, path, bucketName, objectPrefix string, cmm materials.CryptographicMaterialsManager) error {
	var objectKeys []string

	// 指定されたオブジェクトキーがフォルダか単一のオブジェクトを指しているのか判断
	// フォルダの場合、フォルダ配下の全オブジェクトを取得
	// ファイルの場合、オブジェクトキーを直接利用
	if strings.HasSuffix(objectPrefix, "/") {
		listInput := &s3.ListObjectsV2Input{
			Bucket: aws.String(bucketName),
			Prefix: aws.String(objectPrefix),
		}
		res, err := s3Client.ListObjectsV2(ctx, listInput)
		if err != nil {
			return fmt.Errorf("error ListObjectsV2: %w", err)
		}
		for _, item := range res.Contents {
			objectKeys = append(objectKeys, *item.Key)
		}
	} else {
		objectKeys = append(objectKeys, objectPrefix)
	}

	for _, objectKey := range objectKeys {
		var localFilePath string = ""
		if strings.HasSuffix(objectPrefix, "/") || len(objectKeys) > 1 {
			// 複数オブジェクトの場合はプレフィックスを結合し、ディレクトリ構造を維持する
			localFilePath = filepath.Join(path, strings.TrimPrefix(objectKey, objectPrefix))
		} else {
			// 単一オブジェクトの場合
			localFilePath = filepath.Join(path, filepath.Base(objectKey))
		}

		// Get先のディレクトリの作成
		if err := os.MkdirAll(filepath.Dir(localFilePath), os.ModePerm); err != nil {
			return fmt.Errorf("error create directory: %w", err)
		}

		log.Printf("Downloading: %s/%s → %s", bucketName, objectKey, localFilePath)

		// オブジェクトのGet
		getRes, err := s3EncryptionClient.GetObject(ctx, &s3.GetObjectInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(objectKey),
		})
		if err != nil {
			return fmt.Errorf("error while decrypting: %v", err)
		}
		defer getRes.Body.Close()

		file, err := os.Create(localFilePath)
		if err != nil {
			return fmt.Errorf("error create file: %w", err)
		}
		defer file.Close()

		if _, err = file.ReadFrom(getRes.Body); err != nil {
			return fmt.Errorf("error write file: %w", err)
		}
	}

	return nil
}

func PutObjectsWithCseKms(ctx context.Context, s3EncryptionClient *client.S3EncryptionClientV3, s3Client *s3.Client, basePath, bucketName, objectPrefix string, cmm materials.CryptographicMaterialsManager) error {

	return filepath.Walk(basePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			defer file.Close()

			var objectKey string
			if strings.HasSuffix(objectPrefix, "/") {
				// ディレクトリの階層構造を維持するようにオブジェクトキーを生成
				relPath, err := filepath.Rel(basePath, path)
				if err != nil {
					return err
				}

				// relPathが"."の場合 = basePath が単一ファイルの場合はファイル名をそのままオブジェクキーとして使用
				if relPath == "." {
					relPath = filepath.Base(path)
				}

				objectKey = filepath.Join(objectPrefix, relPath)
			} else {
				// objectPrefixをそのままオブジェクトキーとして使用
				objectKey = objectPrefix
			}

			// Windowsのパス区切り文字を正しい形式に変換
			objectKey = filepath.ToSlash(objectKey)

			log.Printf("Uploading: %s → %s/%s", path, bucketName, objectKey)

			_, err = s3EncryptionClient.PutObject(ctx, &s3.PutObjectInput{
				Bucket: &bucketName,
				Key:    &objectKey,
				Body:   file,
			})
			if err != nil {
				return fmt.Errorf("failed to upload %s → %s/%s: %w", path, bucketName, objectKey, err)
			}
		}
		return nil
	})
}
