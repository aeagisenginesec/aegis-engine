package cloudformation

import (
	"testing"
)

// Phase B tests: CFN adapter gaps closed for the R6 recall items.
// Each test scans a template end-to-end through the full AWS rule
// registry, so it pins the adapter shape AND the rule firing together.

// P0-1: RDS PubliclyAccessible via !Ref to a parameter whose default is
// the string "true" (r6054 shape). The string default must resolve as a
// boolean for AEGIS-AWS-011.

func TestPhaseB_RDSRefBoolDefaultFires(t *testing.T) {
	src := `AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  PublicAccess:
    Type: String
    Default: "true"
Resources:
  DB:
    Type: AWS::RDS::DBInstance
    Properties:
      Engine: postgres
      PubliclyAccessible: !Ref PublicAccess
`
	ids := ruleIDs(scanTemplate(t, "t.yaml", src))
	if !ids["AEGIS-AWS-011"] {
		t.Fatalf("expected AEGIS-AWS-011 to fire, got %v", ids)
	}
}

func TestPhaseB_RDSRefBoolFalseQuiet(t *testing.T) {
	src := `AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  PublicAccess:
    Type: String
    Default: "false"
Resources:
  DB:
    Type: AWS::RDS::DBInstance
    Properties:
      Engine: postgres
      PubliclyAccessible: !Ref PublicAccess
`
	ids := ruleIDs(scanTemplate(t, "t.yaml", src))
	if ids["AEGIS-AWS-011"] {
		t.Fatalf("expected AEGIS-AWS-011 quiet for Default false, got %v", ids)
	}
}

// P0-2: ApiGateway Method with AuthorizationType NONE (r6041 shape).

func TestPhaseB_ApiGatewayMethodNoAuthFires(t *testing.T) {
	src := `AWSTemplateFormatVersion: '2010-09-09'
Resources:
  RestApi:
    Type: AWS::ApiGateway::RestApi
    Properties:
      Name: demo
  Method:
    Type: AWS::ApiGateway::Method
    Properties:
      RestApiId: !Ref RestApi
      ResourceId: abc123
      HttpMethod: GET
      AuthorizationType: NONE
`
	ids := ruleIDs(scanTemplate(t, "t.yaml", src))
	if !ids["AEGIS-AWS-403"] {
		t.Fatalf("expected AEGIS-AWS-403 to fire, got %v", ids)
	}
}

func TestPhaseB_ApiGatewayMethodIAMQuiet(t *testing.T) {
	src := `AWSTemplateFormatVersion: '2010-09-09'
Resources:
  RestApi:
    Type: AWS::ApiGateway::RestApi
    Properties:
      Name: demo
  Method:
    Type: AWS::ApiGateway::Method
    Properties:
      RestApiId: !Ref RestApi
      ResourceId: abc123
      HttpMethod: GET
      AuthorizationType: AWS_IAM
`
	ids := ruleIDs(scanTemplate(t, "t.yaml", src))
	if ids["AEGIS-AWS-403"] {
		t.Fatalf("expected AEGIS-AWS-403 quiet for AWS_IAM, got %v", ids)
	}
}

// P0-3: SQS QueuePolicy with a public principal and an unresolvable
// !GetAtt in Resource (r6047 shape). The lenient policy encoder must
// not abort the whole document on the !GetAtt.

func TestPhaseB_SQSQueuePolicyPublicFires(t *testing.T) {
	src := `AWSTemplateFormatVersion: '2010-09-09'
Resources:
  OrdersQueue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: orders
  QueuePolicy:
    Type: AWS::SQS::QueuePolicy
    Properties:
      Queues:
        - !Ref OrdersQueue
      PolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal: "*"
            Action: SQS:*
            Resource: !GetAtt OrdersQueue.Arn
`
	ids := ruleIDs(scanTemplate(t, "t.yaml", src))
	if !ids["AEGIS-AWS-344"] {
		t.Fatalf("expected AEGIS-AWS-344 to fire, got %v", ids)
	}
}

func TestPhaseB_SQSQueuePolicyPrivateQuiet(t *testing.T) {
	src := `AWSTemplateFormatVersion: '2010-09-09'
Resources:
  OrdersQueue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: orders
  QueuePolicy:
    Type: AWS::SQS::QueuePolicy
    Properties:
      Queues:
        - !Ref OrdersQueue
      PolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              AWS: "arn:aws:iam::123456789012:root"
            Action: SQS:*
            Resource: !GetAtt OrdersQueue.Arn
`
	ids := ruleIDs(scanTemplate(t, "t.yaml", src))
	if ids["AEGIS-AWS-344"] {
		t.Fatalf("expected AEGIS-AWS-344 quiet for account principal, got %v", ids)
	}
}

// P1-1: SNS TopicPolicy, same public-principal shape (r6066).

func TestPhaseB_SNSTopicPolicyPublicFires(t *testing.T) {
	src := `AWSTemplateFormatVersion: '2010-09-09'
Resources:
  Topic:
    Type: AWS::SNS::Topic
    Properties:
      TopicName: alerts
  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref Topic
      PolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal: "*"
            Action: SNS:Publish
            Resource: !GetAtt Topic.TopicArn
`
	ids := ruleIDs(scanTemplate(t, "t.yaml", src))
	if !ids["AEGIS-AWS-343"] {
		t.Fatalf("expected AEGIS-AWS-343 to fire, got %v", ids)
	}
}

// P1-2: ECR RepositoryPolicy with PolicyText as a mapping (r6056 shape).

func TestPhaseB_ECRRepositoryPolicyPublicFires(t *testing.T) {
	src := `AWSTemplateFormatVersion: '2010-09-09'
Resources:
  Repo:
    Type: AWS::ECR::Repository
    Properties:
      RepositoryName: app
  RepoPolicy:
    Type: AWS::ECR::RepositoryPolicy
    Properties:
      RepositoryName: !Ref Repo
      PolicyText:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal: "*"
            Action:
              - ecr:GetDownloadUrlForLayer
              - ecr:BatchGetImage
`
	ids := ruleIDs(scanTemplate(t, "t.yaml", src))
	if !ids["AEGIS-AWS-408"] {
		t.Fatalf("expected AEGIS-AWS-408 to fire, got %v", ids)
	}
}
