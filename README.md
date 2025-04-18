# mofh-vp-api-wrapper

mofh-vp-api-wrapper is a powerful VistaPanel API client library written in PHP. It empowers developers to build custom control panels and seamlessly interact with VistaPanel, a robust web hosting control panel. With mofh-vp-api-wrapper, you can manage websites, databases, domains, redirects, SSL certificates, and more, all programmatically using the VistaPanel API (Application Programming Interface).

VistaPanel is a web hosting control panel that allows users to manage their websites, databases, and other aspects of their hosting environment. A VistaPanel API client is a program that can interact with VistaPanel using the VistaPanel API (Application Programming Interface). The API provides a set of methods that can be used to manage various aspects of the hosting environment programmatically.

# API Documentation

The VistaPanel Users API allows you to interact with the VistaPanel hosting control panel using PHP. It provides methods for performing various tasks such as logging in, managing databases, working with domains, creating redirects, uploading SSL certificates, and more.

## Class: VistapanelApi

### Properties

- `cpanelUrl`: The URL of the VistaPanel control panel.
- `loggedIn`: Indicates whether the user is logged in or not.
- `vistapanelSession`: The session ID obtained after logging in.
- `vistapanelSessionName`: The name of the session cookie.
- `vistapanelToken`: The token used for API requests.
- `accountUsername`: The username of the logged-in account.
- `cookie`: The cookie string used for authentication.

### Methods

#### `setCpanelUrl($url)`

Sets the URL of the VistaPanel control panel.

- `$url` (string): The URL of the control panel.

#### `login($username, $password, $theme)`

Logs in to the VistaPanel control panel.

- `$username` (string): The username of the account.
- `$password` (string): The password of the account.
- `$theme` (string): The theme to use after logging in (default: "PaperLantern").

#### `createDatabase($dbname)`

Creates a new database.

- `$dbname` (string): The name of the database, without the account prefix.

#### `listDatabases()`

Returns an array of databases associated with the logged-in account.

#### `deleteDatabase($database)`

Deletes a database.

- `$database` (string): The name of the database, without the account prefix.

#### `getPhpmyadminLink($database)`

Returns the phpMyAdmin link for a specific database.

- `$database` (string): The name of the database, without the account prefix.

#### `listDomains($option)`

Returns an array of domains in a specific category.

- `$option` (string): The category of domains to retrieve. Available options: "all," "addon," "sub," and "parked" (default: "all").

#### `createRedirect($domainname, $target)`

Creates a redirect for a domain.

- `$domainname` (string): The name of the domain.
- `$target` (string): The target URL for the redirect.

#### `deleteRedirect($domainname)`

Deletes a redirect for a domain.

- `$domainname` (string): The name of the domain.

#### `uploadKey($domainname, $key, $csr)`

Uploads an SSL key for a domain.

- `$domainname` (string): The name of the domain.
- `$key` (string): The content of the SSL key file.
- `$csr` (string): The content of the Certificate Signing Request (CSR) file.

#### `uploadCert($domainname, $cert)`

Uploads an SSL certificate for a domain.

- `$domainname` (string): The name of the domain.
- `$cert` (string): The content of the SSL certificate file.

#### `getSSLPrivateKey($domain)`

Get the currently installed SSL key for a domain.

- `$domain` (string): The name of the domain.

#### `getSSLCertificate($domain)`

Get the currently installed SSL certificate for a domain.

- `$domain` (string): The name of the domain.

#### `getSoftaculousLink()`

Returns the Softaculous link for the control panel.

#### `logout()`

Logs out from the control panel, and resets client configuration.

#### `approveNotification()`

Allows iFastNet to send you notifications about account suspensions, also unlocks the control panel.

## Example Usage

```php
<?php
require_once 'api-client.php';

$mofh-vp-api-wrapper = new VistapanelApi();
$mofh-vp-api-wrapper->setCpanelUrl('https://cpanel.example.com');
$mofh-vp-api-wrapper->login('username', 'password');

$databases = $mofh-vp-api-wrapper->listDatabases();
foreach ($databases as $database => $value) {
    echo $database . "\n";
}

$mofh-vp-api-wrapper->logout();
?>
```

Successor to VPClient/GenerateClient and Fork of [VistaPanel PHP API](https://github.com/oddmario/vistapanel-php-api).
