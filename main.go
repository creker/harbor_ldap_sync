package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/go-resty/resty/v2"
)

func syncUsers(client *resty.Client, verbose bool) error {
	// find all LDAP users
	var search []struct {
		Username string
	}
	resp, err := client.R().SetResult(&search).Get("api/v2.0/ldap/users/search")
	if err != nil {
		return fmt.Errorf("failed to search LDAP: %w", err)
	}
	if resp.StatusCode() != 200 {
		return fmt.Errorf("search existing returned %s %s", resp.Status(), resp.String())
	}

	ldapMap := make(map[string]struct{}, len(search))
	for _, u := range search {
		ldapMap[u.Username] = struct{}{}
	}
	if verbose {
		fmt.Println("LDAP user search returned", search)
	}

	// filter out existing users
	for i := 0; ; i++ {
		var search []struct {
			Username string
		}
		resp, err := client.R().SetQueryParams(map[string]string{"page_size": "100", "page": strconv.Itoa(i)}).SetResult(&search).Get("api/v2.0/users")
		if err != nil {
			return fmt.Errorf("failed to search existing: %w", err)
		}
		if resp.StatusCode() != 200 {
			return fmt.Errorf("search existing returned %s %s", resp.Status(), resp.String())
		}

		for i := range search {
			delete(ldapMap, search[i].Username)
		}
		if len(search) < 100 {
			break
		}
	}
	if len(ldapMap) == 0 {
		fmt.Println("no new LDAP users")
		return nil
	}

	// add new LDAP users
	uidList := struct {
		List []string `json:"ldap_uid_list"`
	}{List: make([]string, 0, len(ldapMap))}
	for i := range ldapMap {
		uidList.List = append(uidList.List, i)
	}

	resp, err = client.R().SetBody(uidList).Post("api/v2.0/ldap/users/import")
	if err != nil {
		return fmt.Errorf("failed to import: %w", err)
	}
	if resp.StatusCode() != 200 {
		return fmt.Errorf("import returned %s %s", resp.Status(), resp.String())
	}

	fmt.Println("new LDAP users", uidList.List)

	return nil
}

type ldapConfig struct {
	url         string
	searchDN    string
	groupBaseDN string
	groupFilter string
	groupAttr   string
	scope       int
	verifyCert  bool
}

func getLdapConfig(client *resty.Client, verbose bool) (ldapConfig, error) {
	var rawCfg map[string]struct{ Value interface{} }
	resp, err := client.R().SetResult(&rawCfg).Get("api/v2.0/configurations")
	if err != nil {
		return ldapConfig{}, fmt.Errorf("request failed: %w", err)
	}
	if resp.StatusCode() != 200 {
		return ldapConfig{}, fmt.Errorf("request returned %s %s", resp.Status(), resp.String())
	}
	if verbose {
		fmt.Println("harbor config:", rawCfg)
	}

	cfg := ldapConfig{scope: 2, groupAttr: "cn", verifyCert: true}
	if v, ok := rawCfg["ldap_url"]; ok {
		cfg.url, ok = v.Value.(string)
		if !ok {
			return ldapConfig{}, fmt.Errorf("ldap_url is not string: %v(%T)", v.Value, v.Value)
		}
		if cfg.url == "" {
			return ldapConfig{}, fmt.Errorf("ldap_url is missing")
		}
	}
	if v, ok := rawCfg["ldap_search_dn"]; ok {
		cfg.searchDN, ok = v.Value.(string)
		if !ok {
			return ldapConfig{}, fmt.Errorf("ldap_search_dn is not string: %v(%T)", v.Value, v.Value)
		}
		if cfg.searchDN == "" {
			return ldapConfig{}, fmt.Errorf("ldap_search_dn is missing")
		}
	}
	if v, ok := rawCfg["ldap_group_base_dn"]; ok {
		cfg.groupBaseDN, ok = v.Value.(string)
		if !ok {
			return ldapConfig{}, fmt.Errorf("ldap_group_base_dn is not string: %v(%T)", v.Value, v.Value)
		}
		if cfg.groupBaseDN == "" {
			return ldapConfig{}, fmt.Errorf("ldap_group_base_dn is missing")
		}
	}
	if v, ok := rawCfg["ldap_group_search_filter"]; ok {
		cfg.groupFilter, ok = v.Value.(string)
		if !ok {
			return ldapConfig{}, fmt.Errorf("ldap_group_search_filter is not string: %v(%T)", v.Value, v.Value)
		}
		if cfg.groupFilter == "" {
			return ldapConfig{}, fmt.Errorf("ldap_group_search_filter is missing")
		}
	}
	if v, ok := rawCfg["ldap_group_attribute_name"]; ok {
		cfg.groupAttr, ok = v.Value.(string)
		if !ok {
			return ldapConfig{}, fmt.Errorf("ldap_group_attribute_name is not string: %v(%T)", v.Value, v.Value)
		}
		if cfg.groupAttr == "" {
			return ldapConfig{}, fmt.Errorf("ldap_group_attribute_name is missing")
		}
	}
	if v, ok := rawCfg["ldap_group_search_scope"]; ok {
		vv, ok := v.Value.(float64)
		if !ok {
			return ldapConfig{}, fmt.Errorf("ldap_group_search_scope is not int: %v(%T)", v.Value, v.Value)
		}
		cfg.scope = int(vv)
	}
	if v, ok := rawCfg["ldap_verify_cert"]; ok {
		cfg.verifyCert, ok = v.Value.(bool)
		if !ok {
			return ldapConfig{}, fmt.Errorf("ldap_verify_cert is not bool: %v(%T)", v.Value, v.Value)
		}
	}

	return cfg, nil
}

func syncGroups(client *resty.Client, ldapPass string, verbose bool) error {
	cfg, err := getLdapConfig(client, verbose)
	if err != nil {
		return fmt.Errorf("failed to get LDAP config: %w", err)
	}
	if verbose {
		fmt.Println("LDAP config:", cfg)
	}

	existingGroups := make(map[string]struct{})
	for i := 0; ; i++ {
		const pageSize = 100
		var search []struct {
			DN string `json:"ldap_group_dn"`
		}
		resp, err := client.R().SetQueryParams(map[string]string{"page": strconv.Itoa(i), "page_size": strconv.Itoa(pageSize)}).SetResult(&search).Get("api/v2.0/usergroups")
		if err != nil {
			return fmt.Errorf("failed to search: %w", err)
		}
		if resp.StatusCode() != 200 {
			return fmt.Errorf("search returned %s %s", resp.Status(), resp.String())
		}

		for i := range search {
			existingGroups[search[i].DN] = struct{}{}
		}
		if len(search) < pageSize {
			break
		}
	}

	conn, err := ldap.DialURL(cfg.url, ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: !cfg.verifyCert}))
	if err != nil {
		return fmt.Errorf("failed to connect to LDAP: %w", err)
	}
	if cfg.searchDN != "" && ldapPass != "" {
		if err := conn.Bind(cfg.searchDN, ldapPass); err != nil {
			return fmt.Errorf("failed to bind: %w", err)
		}
	}

	scope := ldap.ScopeWholeSubtree
	switch cfg.scope {
	case 0:
		scope = ldap.ScopeBaseObject
	case 1:
		scope = ldap.ScopeSingleLevel
	case 2:
		scope = ldap.ScopeWholeSubtree
	}
	result, err := conn.Search(ldap.NewSearchRequest(cfg.groupBaseDN, scope, 0, 0, 0, false, cfg.groupFilter, []string{cfg.groupAttr}, nil))
	if err != nil {
		return fmt.Errorf("failed to search LDAP: %w", err)
	}

	didInsert := false
	for _, e := range result.Entries {
		if _, ok := existingGroups[e.DN]; ok {
			if verbose {
				fmt.Println(e.DN, "already exists")
			}
			continue
		}

		g := struct {
			Name string `json:"group_name"`
			DN   string `json:"ldap_group_dn"`
			Type int    `json:"group_type"`
		}{
			Name: e.GetAttributeValue(cfg.groupAttr),
			DN:   e.DN,
			Type: 1,
		}

		resp, err := client.R().SetBody(g).Post("api/v2.0/usergroups")
		if err != nil {
			return fmt.Errorf("insert request failed: %w", err)
		}
		if resp.StatusCode() != 201 && resp.StatusCode() != 409 {
			return fmt.Errorf("insert request returned %s %s", resp.Status(), resp.String())
		}
		if resp.StatusCode() == 201 {
			fmt.Println("created", e.DN)
		} else {
			fmt.Println(e.DN, "already exists but wasn't filtered out")
		}
		didInsert = true
	}
	if !didInsert {
		fmt.Println("no new LDAP groups")
	}

	return nil
}

func main() {
	sync := flag.String("sync", "", "comma delimited sync types (users, groups). Required. Example: users,groups")
	harborUrl := flag.String("harbor_url", "", "required")
	harborLogin := flag.String("harbor_login", "", "required")
	harborPass := flag.String("harbor_pass", os.Getenv("HLS_HARBOR_PASS"), "required. Can be set with HLS_HARBOR_PASS")
	ldapPass := flag.String("ldap_pass", os.Getenv("HLS_LDAP_PASS"), "LDAP search password specified in Harbor config. Can be set with HLS_LDAP_PASS")
	verbose := flag.Bool("verbose", false, "")
	flag.Parse()
	if *sync == "" ||
		*harborUrl == "" ||
		*harborLogin == "" ||
		*harborPass == "" {
		flag.PrintDefaults()
		return
	}

	doSyncUsers := false
	doSyncGroups := false
	dedup := make(map[string]struct{})
	for _, s := range strings.Split(*sync, ",") {
		s = strings.Trim(strings.ToLower(s), " ")
		if _, ok := dedup[s]; ok {
			continue
		}
		dedup[s] = struct{}{}
		switch s {
		case "users":
			doSyncUsers = true
		case "groups":
			doSyncGroups = true
		default:
			fmt.Println("unknown sync type")
			flag.PrintDefaults()
		}
	}

	didFail := false
	client := resty.New().SetBasicAuth(*harborLogin, *harborPass).SetBaseURL(*harborUrl).SetCookieJar(nil)
	if doSyncUsers {
		if err := syncUsers(client, *verbose); err != nil {
			fmt.Println("user sync failed:", err)
			didFail = true
		}
	}
	if doSyncGroups {
		if err := syncGroups(client, *ldapPass, *verbose); err != nil {
			fmt.Println("group sync failed:", err)
			didFail = true
		}
	}
	if didFail {
		os.Exit(1)
	}
}
