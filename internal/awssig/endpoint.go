package awssig

import (
	"net"
	"regexp"
	"strings"
)

// defaultRegion is where AWS's global endpoints, such as iam and sts, are
// signed.
const defaultRegion = "us-east-1"

var regionRE = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-\d+$`)

// Endpoint derives the signing service and region from an AWS hostname:
//
//	iam.amazonaws.com                  iam, us-east-1
//	dynamodb.eu-central-1.amazonaws.com dynamodb, eu-central-1
//	bucket.s3.us-west-2.amazonaws.com  s3, us-west-2
//
// Hostnames outside these shapes, including the legacy "s3-us-west-2" form,
// are not derived; name the service and region on the rule instead.
func Endpoint(host string) (service, region string, ok bool) {
	host = strings.ToLower(strings.TrimSpace(host))
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(host, ".")

	rest, ok := strings.CutSuffix(host, ".amazonaws.com.cn")
	if !ok {
		if rest, ok = strings.CutSuffix(host, ".amazonaws.com"); !ok {
			return "", "", false
		}
	}

	labels := strings.Split(rest, ".")
	region = defaultRegion
	if last := labels[len(labels)-1]; regionRE.MatchString(last) {
		region = last
		labels = labels[:len(labels)-1]
	}
	if len(labels) == 0 {
		return "", "", false
	}
	service = labels[len(labels)-1]
	if service == "" {
		return "", "", false
	}
	return service, region, true
}
