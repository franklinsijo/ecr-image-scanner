package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/ghodss/yaml"

	"github.com/aws/aws-sdk-go/service/ecr"

	"gopkg.in/urfave/cli.v2"
)

// Version ...
const Version = "0.1.0"

var (
	profile, role, thresholdsYAML string
	mandateScan                   bool
	err                           error
)

func getClient(region string) *ecr.ECR {
	var ecrClient *ecr.ECR
	sess := session.Must(session.NewSession())
	ecrClient = ecr.New(sess, &aws.Config{Region: aws.String(region)})
	if role != "" {
		ecrClient = ecr.New(sess, &aws.Config{
			Region:      aws.String(region),
			Credentials: stscreds.NewCredentials(sess, role)},
		)
	} else if profile != "" {
		sess = session.Must(session.NewSessionWithOptions(
			session.Options{
				Profile: profile,
				Config: aws.Config{
					Region: aws.String(region),
				},
				SharedConfigState: session.SharedConfigEnable,
			},
		))
		ecrClient = ecr.New(sess, &aws.Config{Region: aws.String(region)})
	}
	return ecrClient
}

func isUnderControl(a, e map[string]*int64) bool {
	severityOrder := [6]string{"UNDEFINED", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"}
	for _, sev := range severityOrder {
		if ev, ok := e[sev]; ok {
			if av, ok := a[sev]; ok {
				if *av > *ev {
					return false
				}
			}
		}
	}
	return true
}

func scanImage(uri string) error {
	uriRe := regexp.MustCompile(`^([0-9]{12})\.dkr\.ecr\.([a-z]{2}-[a-z]{4,}-[1-9])\.amazonaws\.com\/(\S[^:]*):?([a-zA-Z0-9.-_]*)$`)
	vars := uriRe.FindStringSubmatch(uri)
	if vars != nil {
		if len(vars) < 4 {
			return fmt.Errorf("invalid ecr repository uri")
		}
		if vars[4] == "" {
			vars[4] = "latest"
		}
		ecrClient := getClient(vars[2])

		getScanFindings := func() (*ecr.DescribeImageScanFindingsOutput, error) {
			var scanFindings []*ecr.ImageScanFinding
			var scanFindingsResult *ecr.DescribeImageScanFindingsOutput
			hasNext := true
			nextToken := ""
			for hasNext {
				var scanFindingsInput *ecr.DescribeImageScanFindingsInput
				if nextToken != "" {
					scanFindingsInput = &ecr.DescribeImageScanFindingsInput{
						RegistryId:     aws.String(vars[1]),
						RepositoryName: aws.String(vars[3]),
						ImageId:        &ecr.ImageIdentifier{ImageTag: aws.String(vars[4])},
						MaxResults:     aws.Int64(1),
						NextToken:      aws.String(nextToken),
					}
				} else {
					scanFindingsInput = &ecr.DescribeImageScanFindingsInput{
						RegistryId:     aws.String(vars[1]),
						RepositoryName: aws.String(vars[3]),
						ImageId:        &ecr.ImageIdentifier{ImageTag: aws.String(vars[4])},
						MaxResults:     aws.Int64(1),
					}
				}
				scanFindingsResult, err = ecrClient.DescribeImageScanFindings(scanFindingsInput)
				if err != nil {
					return scanFindingsResult, err
				}
				if *scanFindingsResult.ImageScanStatus.Status == "COMPLETE" {
					if scanFindingsResult.NextToken != nil {
						nextToken = *scanFindingsResult.NextToken
					} else {
						hasNext = false
					}
					scanFindings = append(scanFindings, scanFindingsResult.ImageScanFindings.Findings...)
				} else {
					if *scanFindingsResult.ImageScanStatus.Status == "IN_PROGRESS" {
						log.Println("INFO: scanning in progress")
						time.Sleep(1 * time.Second)
						continue
					}
					return scanFindingsResult, fmt.Errorf("image scan status %s", *scanFindingsResult.ImageScanStatus.Status)
				}
			}
			scanFindingsResult.ImageScanFindings.Findings = scanFindings
			return scanFindingsResult, nil
		}

		_, err = ecrClient.StartImageScan(&ecr.StartImageScanInput{
			RegistryId:     aws.String(vars[1]),
			RepositoryName: aws.String(vars[3]),
			ImageId:        &ecr.ImageIdentifier{ImageTag: aws.String(vars[4])},
		})
		isThrottled := false
		if err != nil {
			if aerr, ok := err.(awserr.Error); ok {
				if aerr.Code() == "ThrottlingException" {
					isThrottled = true
				} else {
					return fmt.Errorf("failed to scan the image\n%v", err)
				}
			} else {
				return fmt.Errorf("failed to scan the image\n%v", err)
			}
		}
		scanResult, err := getScanFindings()
		if err != nil {
			return fmt.Errorf("failed to get the scan findings.\n%v", err)
		}
		if isThrottled {
			log.Println("INFO: last scan was performed at", *scanResult.ImageScanFindings.ImageScanCompletedAt)
		}

		if mandateScan && isThrottled {
			return fmt.Errorf("scan limit reached for %s", uri)
		}
		log.Println("INFO: found vulnerabilities")
		for severity, counts := range scanResult.ImageScanFindings.FindingSeverityCounts {
			fmt.Println(severity, *counts)
		}
		if thresholdsYAML != "" {
			thresholds, err := ioutil.ReadFile(thresholdsYAML)
			if err != nil {
				return fmt.Errorf("failed to read the thresholds file %s\n%v", thresholdsYAML, err)
			}
			var sevCounts map[string]*int64
			err = yaml.Unmarshal(thresholds, &sevCounts)
			if err != nil {
				return fmt.Errorf("failed to unmarshal json object\n%v", err)
			}
			log.Println("INFO: thresholds defined for vulnerabilities of various severities")
			for severity, counts := range sevCounts {
				fmt.Println(severity, *counts)
			}
			status := isUnderControl(scanResult.ImageScanFindings.FindingSeverityCounts, sevCounts)
			if !status {
				return fmt.Errorf("vulnerabilities found in the image exceeds the defined thresholds")
			}
			log.Println("INFO: vulnerabilities found in the image are under the defined thresholds")
		}
	} else {
		return fmt.Errorf("invalid ecr repository uri")
	}
	return nil
}

func main() {
	scanImage := func(ctx *cli.Context) error {
		if ctx.NArg() < 1 {
			return fmt.Errorf("ecr-repo-uri argument is required")
		}
		uri := ctx.Args().Get(0)
		err := scanImage(uri)
		if err != nil {
			return err
		}
		return nil
	}
	app := cli.App{
		Usage:       "Utility to perform ECR image scanning on demand",
		Description: "Use this tool to perform vulnerability scanning on ecr repositories on demand",
		Version:     Version,
		UsageText:   "ecr_scan [global options] <ecr-repo-uri>",
		Action:      scanImage,
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "profile", EnvVars: []string{"AWS_PROFILE"}, Destination: &profile, Usage: "name of the `AWS_PROFILE` to use"},
			&cli.StringFlag{Name: "role", EnvVars: []string{"AWS_ROLE"}, Destination: &role, Usage: "`ARN` of the IAM Role to assume"},
			&cli.StringFlag{Name: "thresholds", Aliases: []string{"t"}, Destination: &thresholdsYAML, Usage: "path of the `YAML_FILE` with severity count thresholds"},
			&cli.BoolFlag{Name: "mandatory", Aliases: []string{"m"}, Value: false, Destination: &mandateScan, Usage: "fail if scan cannot be completed due to throttling"},
		},
	}
	err = app.Run(os.Args)
	if err != nil {
		log.Fatalln("ERROR:", err.Error())
	}
}
