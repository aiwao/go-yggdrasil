package yggdrasil

import "testing"

func Test(t *testing.T) {
    AuthServer = "http://authserver.thealtening.com"
    username := "example@alt.com"
    password := "anything"
    yggdrasilClient := &Client{}
    authRes, err := yggdrasilClient.Authenticate(username, password)
    if err != nil {
        t.Fatal(err)
    }
    t.Logf("\nUsername: %s\nUUID: %s", authRes.SelectedProfile.Name, authRes.SelectedProfile.ID)

    refresh, err := yggdrasilClient.Refresh()
    if err != nil {
        t.Fatal(err)
    }
    t.Logf("\nRefreshed:\n  Username: %s\n  UUID: %s", refresh.SelectedProfile.Name, refresh.SelectedProfile.ID)

    success, err := yggdrasilClient.Signout(username, password)
    if err != nil {
        t.Fatal(err)
    }

    if success {
        t.Logf("Signout success")
    } else {
        t.Logf("Signout failed")
    }
}
