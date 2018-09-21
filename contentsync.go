package ldap

import (
	"errors"
	"fmt"
)

const (
	refreshOnly       = 1
	refreshAndPersist = 3
)

func GetContentSyncRequest(baseDn, filter string, cookie []byte) *SearchRequest {
	sizeLimit := 0
	timeLimit := 0
	typesOnly := false

	reloadHint := false
	if cookie != nil {
		reloadHint = true
	}

	contentSyncControl := NewControlContentSync(refreshAndPersist, reloadHint, cookie)

	searchRequest := NewSearchRequest(
		baseDn, ScopeWholeSubtree, NeverDerefAliases,
		sizeLimit, timeLimit, typesOnly, filter,
		nil,
		[]Control{contentSyncControl},
	)

	return searchRequest
}

func (l *Conn) RunContentSync(searchRequest *SearchRequest, entryCallback EntryCallback, cookieCallback CookieCallback) error {
	l.entryCallback = func(entry *Entry, controls []Control) error {

		if len(controls) == 0 {
			// FreeIPA sends duplicate objects in "compatability" mode.  These won't have any controls.
			return nil
		}

		control, err := getContentSyncStateControl(controls)
		if err != nil {
			return err
		}

		if err := entryCallback(entry, control.Uuid, control.State); err != nil {
			return err
		}

		// Update and Delete events come with the cookie, and a separate cookie message will not arrive
		if control.Cookie != nil && len(control.Cookie) > 0 {
			return cookieCallback(control.Cookie)
		}

		return nil
	}

	l.cookieCallback = func(cookie []byte) error {
		return cookieCallback(cookie)
	}

	l.referalCallback = func(referal string) error {
		// TODO: what do we do with this?
		return nil
	}

	_, err := l.Search(searchRequest)
	return err
}

func getContentSyncStateControl(controls []Control) (*ControlContentSyncState, error) {
	control := FindControl(controls, ControlTypeContentSyncState)
	if control == nil {
		return nil, errors.New("ldap: no content sync state control found")
	}

	contentSyncState, ok := control.(*ControlContentSyncState)
	if !ok {
		return nil, fmt.Errorf("ldap: expected ControlContentSyncState control, but got %T", control)
	}

	return contentSyncState, nil
}
