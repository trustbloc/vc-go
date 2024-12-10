/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package identityhub implements a subset of Identity Hub data models, to support requesting identity hub data.
package identityhub

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/trustbloc/did-go/doc/did"
	model "github.com/trustbloc/did-go/doc/did/endpoint"
)

// Request contains an identity hub query.
type Request struct {
	RequestID string    `json:"requestId"`
	Target    string    `json:"target"`
	Messages  []Message `json:"messages"`
}

// Response contains the results of an identity hub query.
type Response struct {
	RequestID string          `json:"requestId"`
	Status    *Status         `json:"status"`
	Replies   []MessageResult `json:"replies"`
}

// MessageResult holds a set of messages inside an identity hub response.
type MessageResult struct {
	MessageID string    `json:"messageId"`
	Status    Status    `json:"status"`
	Entries   []Message `json:"entries,omitempty"`
}

// Message holds a single data element inside an identity hub response.
type Message struct {
	Descriptor map[string]interface{} `json:"descriptor"`
	Data       string                 `json:"data,omitempty"`
}

// Status holds a http status code and error message, for an identity hub response or message result.
type Status struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

const (
	methodKey              = "method"
	objectIDKey            = "objectId"
	serviceTypeIdentityHub = "IdentityHub"
)

// CheckStatus returns an error if this Response or any MessageResult within has a status other than http.StatusOK.
func (i Response) CheckStatus() error {
	if i.Status != nil && i.Status.Code != http.StatusOK {
		return fmt.Errorf(
			"unexpected request level status code, got %d, message: %s",
			i.Status.Code,
			i.Status.Message,
		)
	}

	for _, messageResult := range i.Replies {
		if messageResult.Status.Code != http.StatusOK {
			return fmt.Errorf(
				"unexpected message level status code, got %d, message: %s",
				messageResult.Status.Code,
				messageResult.Status.Message,
			)
		}
	}

	return nil
}

// GetMessageData returns the data for the Message with the given ID inside this Response.
func (i Response) GetMessageData(objectID string) ([]byte, error) {
	for _, messageResult := range i.Replies {
		for _, message := range messageResult.Entries {
			objectIDReceived, ok := message.GetObjectID()
			if !ok || !strings.EqualFold(objectIDReceived, objectID) {
				continue
			}

			messageData, err := base64.StdEncoding.DecodeString(message.Data)
			if err != nil {
				return nil, fmt.Errorf("unable to decode message bytes: %w", err)
			}

			return messageData, nil
		}
	}

	return nil, errors.New("unable to get message by object ID from Response")
}

// GetObjectID returns the objectId of the Message.
func (m Message) GetObjectID() (string, bool) {
	val, ok := m.Descriptor[objectIDKey].(string)

	return val, ok
}

// IsMethod returns true iff the Message matches the given method.
func (m Message) IsMethod(method string) bool {
	v, ok := m.Descriptor[methodKey].(string)

	return ok && strings.EqualFold(v, method)
}

// GetRequest constructs a Request with one message, for the given method, with message descriptor taken from the
// matching method in messageDescriptorData.
// Returns the object ID of the selected message, and the Request.
func GetRequest(
	hubDID, messageMethod string,
	messageDescriptorData []map[string]interface{},
) (string, *Request, error) {
	request := Request{
		RequestID: uuid.NewString(),
		Target:    hubDID,
		Messages:  nil,
	}

	objectID, msg, err := firstValidMessage(messageMethod, messageDescriptorData)
	if err != nil {
		return "", nil, err
	}

	request.Messages = append(request.Messages, *msg)

	return objectID, &request, nil
}

func firstValidMessage(selectMethod string, messageDescriptors []map[string]interface{}) (string, *Message, error) {
	for _, descriptor := range messageDescriptors {
		msg := &Message{Descriptor: descriptor}
		if !msg.IsMethod(selectMethod) {
			continue
		}

		objectID, hasID := msg.GetObjectID()
		if !hasID {
			continue
		}

		return objectID, msg, nil
	}

	return "", nil, fmt.Errorf("objectId is not defined, query %v", messageDescriptors)
}

// ServiceEndpoint returns the identity hub service endpoint URI from the identity hub service of the given DID doc.
func ServiceEndpoint(doc *did.Doc) (string, error) {
	var svc *did.Service

	for i := range doc.Service {
		if doc.Service[i].Type == serviceTypeIdentityHub {
			svc = &(doc.Service[i])

			break
		}
	}

	if svc == nil {
		return "", errors.New("no identity hub service supplied")
	}

	switch svc.ServiceEndpoint.Type() { //nolint:exhaustive
	case model.DIDCommV1, model.DIDCommV2:
		serviceEndpoint, err := svc.ServiceEndpoint.URI()
		if err != nil {
			return "", fmt.Errorf("unable to get service endpoint URL: %w", err)
		}

		return serviceEndpoint, nil
	default:
		return getDIDCoreServiceEndpoint(svc)
	}
}

func getDIDCoreServiceEndpoint(svc *did.Service) (string, error) {
	serviceEndpoint, err := svc.ServiceEndpoint.URI()
	if err == nil {
		return serviceEndpoint, nil
	}

	endpointBytes, err := svc.ServiceEndpoint.MarshalJSON()
	if err != nil {
		return "", fmt.Errorf("unable to marshal DIDCore service endpoint: %w", err)
	}

	var mapped map[string]interface{}
	if err = json.Unmarshal(endpointBytes, &mapped); err != nil {
		return "", fmt.Errorf("unable to unmarshal DIDCore service endpoint: %w", err)
	}

	for _, v := range mapped {
		didCoreEndpoint := model.NewDIDCoreEndpoint(v)

		serviceEndpoint, err = didCoreEndpoint.URI()
		if err == nil {
			return serviceEndpoint, nil
		}
	}

	return "", errors.New("unable to extract DIDCore service endpoint")
}
