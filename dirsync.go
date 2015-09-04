package ldap

import (
	"errors"
	"fmt"
	"time"
)

func GetDirSyncRequest(baseDn string, cookie []byte) *SearchRequest {
	filter := "(objectclass=*)"
	sizeLimit := 0
	timeLimit := 0
	typesOnly := false

	dirSyncControl := NewControlDirSync(0, 1000, cookie)
	dirSyncControlEx := NewControlDirSyncEx(1)

	searchRequest := NewSearchRequest(
		baseDn, ScopeBaseObject, NeverDerefAliases,
		sizeLimit, timeLimit, typesOnly, filter,
		nil,
		[]Control{dirSyncControl, dirSyncControlEx},
	)

	return searchRequest
}

func (l *Conn) RunDirSync(searchRequest *SearchRequest, callback func([]*Entry, []byte) error) error {

	dirSyncControl, err := getDirSyncControl(searchRequest.Controls)
	if err != nil {
		return err
	}

	for {
		result, err := l.Search(searchRequest)
		if err != nil {
			return err
		}

		if result == nil {
			return errors.New("ldap: packet not received")
		}

		dirSync, err := getDirSyncControl(result.Controls)
		if err != nil {
			return err
		}

		cookie := dirSync.Cookie
		if len(cookie) == 0 {
			return errors.New("ldap: dirsync cookie in the result is empty")
		}

		if err := callback(result.Entries, cookie); err != nil {
			return fmt.Errorf("ldap callback returned an error: %v", err)
		}

		if len(result.Entries) == 0 {
			time.Sleep(10 * time.Second)
		} else {
			dirSyncControl.SetCookie(cookie)
		}
	}
}

func getDirSyncControl(controls []Control) (*ControlDirSync, error) {
	control := FindControl(controls, ControlTypeDirSync)
	if control == nil {
		return nil, errors.New("ldap: no dirsync control found")
	}

	dirSync, ok := control.(*ControlDirSync)
	if !ok {
		return nil, fmt.Errorf("ldap: expected ControlDirSync control, but got %T", control)
	}

	return dirSync, nil
}
