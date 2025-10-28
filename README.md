
# 🧩 mofh-vp-api-wrapper

**mofh-vp-api-wrapper** is a powerful PHP client library designed for **VistaPanel**, the control panel used by MyOwnFreeHost (MOFH) resellers.
It enables developers to **programmatically manage websites, databases, domains, redirects, SSL certificates**, and more — all through a clean and simple API interface.

This library is a **successor to VPClient/GenerateClient** and a **modern fork** of [oddmario/vistapanel-php-api](https://github.com/oddmario/vistapanel-php-api).

---

## 🚀 Overview

VistaPanel is the control panel used by MOFH-powered hosting accounts.
The **VistaPanel API** allows automation of hosting management actions such as:

* Logging in and managing sessions
* Creating and deleting MySQL databases
* Managing domains, subdomains, and redirects
* Uploading SSL certificates and keys
* Integrating with Softaculous
* Handling notifications and user sessions programmatically

With **mofh-vp-api-wrapper**, you can easily connect to your VistaPanel instance and automate all of the above using simple PHP methods.

---

## 🧱 Installation

You can include the library manually or install it via Composer (if supported).

### Manual Installation

1. Download the library files.
2. Include it in your PHP script:

```php
require_once 'mofh-vp-api-wrapper.php';
```

---

## 🧠 Class: `Vistapanel_Api`

This is the main class that manages all VistaPanel API operations.

---

### 🧩 Properties

| Property                  | Type   | Description                                             |
| ------------------------- | ------ | ------------------------------------------------------- |
| `cpanel_url`              | string | The base URL of your VistaPanel control panel.          |
| `logged_in`               | bool   | Indicates whether the session is currently logged in.   |
| `vistapanel_session`      | string | The session ID obtained after logging in.               |
| `vistapanel_session_name` | string | The name of the VistaPanel session cookie.              |
| `vistapanel_token`        | string | The token required for API authentication.              |
| `account_username`        | string | The username of the currently logged-in account.        |
| `cookie`                  | string | The full cookie string used for authenticated requests. |

---

## ⚙️ Methods

### 🔹 `set_cpanel_url($url)`

Sets the URL of the VistaPanel control panel.

**Parameters:**

* `$url` *(string)* — The full control panel URL (e.g., `https://cpanel.example.com`)

**Example:**

```php
$api->set_cpanel_url('https://cpanel.example.com');
```

---

### 🔹 `login($username, $password, $theme = 'PaperLantern')`

Logs into the VistaPanel control panel.

**Parameters:**

* `$username` *(string)* — VistaPanel username
* `$password` *(string)* — VistaPanel password
* `$theme` *(string)* — The panel theme (default: `'PaperLantern'`)

**Example:**

```php
$api->login('user123', 'securepassword', 'PaperLantern');
```

---

### 🔹 `create_database($dbname)`

Creates a new MySQL database.

**Parameters:**

* `$dbname` *(string)* — The database name (without account prefix)

**Example:**

```php
$api->create_database('new_db');
```

---

### 🔹 `list_databases()`

Returns an array of all MySQL databases associated with the logged-in account.

**Example:**

```php
$databases = $api->list_databases();
print_r($databases);
```

---

### 🔹 `delete_database($database)`

Deletes a specific MySQL database.

**Parameters:**

* `$database` *(string)* — Database name (without prefix)

**Example:**

```php
$api->delete_database('old_db');
```

---

### 🔹 `get_phpmyadmin_link($database)`

Retrieves the phpMyAdmin login link for a specific database.

**Parameters:**

* `$database` *(string)* — Database name (without prefix)

**Example:**

```php
$link = $api->get_phpmyadmin_link('example_db');
echo $link;
```

---

### 🔹 `list_domains($option = 'all')`

Lists all domains associated with the account.

**Parameters:**

* `$option` *(string)* — The domain type: `'all'`, `'addon'`, `'sub'`, or `'parked'` (default: `'all'`)

**Example:**

```php
$domains = $api->list_domains('addon');
print_r($domains);
```

---

### 🔹 `create_redirect($domainname, $target)`

Creates a redirect from one domain to another.

**Parameters:**

* `$domainname` *(string)* — Source domain name
* `$target` *(string)* — Destination URL

**Example:**

```php
$api->create_redirect('example.com', 'https://newsite.com');
```

---

### 🔹 `delete_redirect($domainname)`

Removes an existing redirect.

**Parameters:**

* `$domainname` *(string)* — Domain name whose redirect should be deleted

**Example:**

```php
$api->delete_redirect('example.com');
```

---

### 🔹 `upload_key($domainname, $key, $csr)`

Uploads a private key and CSR for SSL installation.

**Parameters:**

* `$domainname` *(string)* — Target domain
* `$key` *(string)* — SSL key content
* `$csr` *(string)* — Certificate Signing Request content

**Example:**

```php
$api->upload_key('example.com', $ssl_key, $csr_data);
```

---

### 🔹 `upload_cert($domainname, $cert)`

Uploads an SSL certificate for a domain.

**Parameters:**

* `$domainname` *(string)* — Target domain
* `$cert` *(string)* — SSL certificate content

**Example:**

```php
$api->upload_cert('example.com', $certificate);
```

---

### 🔹 `get_ssl_private_key($domain)`

Retrieves the currently installed SSL private key.

**Parameters:**

* `$domain` *(string)* — Domain name

**Example:**

```php
$key = $api->get_ssl_private_key('example.com');
```

---

### 🔹 `get_ssl_certificate($domain)`

Retrieves the installed SSL certificate.

**Parameters:**

* `$domain` *(string)* — Domain name

**Example:**

```php
$cert = $api->get_ssl_certificate('example.com');
```

---

### 🔹 `get_softaculous_link()`

Returns the Softaculous (auto-installer) URL.

**Example:**

```php
$link = $api->get_softaculous_link();
echo $link;
```

---

### 🔹 `logout()`

Logs out of VistaPanel and resets all client configuration.

**Example:**

```php
$api->logout();
```

---

### 🔹 `approve_notification()`

Allows iFastNet to send suspension and alert notifications to the control panel.
Also unlocks the control panel if locked.

**Example:**

```php
$api->approve_notification();
```

---

## 💻 Example Usage

```php
<?php
require_once 'mofh-vp-api-wrapper.php';

$api = new Vistapanel_Api();
$api->set_cpanel_url('https://cpanel.example.com');
$api->login('username', 'password');

// List all databases
$databases = $api->list_databases();
foreach ($databases as $db) {
    echo $db . PHP_EOL;
}

// Create a new redirect
$api->create_redirect('example.com', 'https://redirectedsite.com');

// Log out when done
$api->logout();
?>
```

---

## 🧩 Related Projects

* [mofh-javascript](https://github.com/MOFHCommunity/mofh-javascript) — Customize VistaPanel with JavaScript
* [oddmario/vistapanel-php-api](https://github.com/oddmario/vistapanel-php-api) — Original PHP API library

---

## ⚖️ License

This project is licensed under the **MIT License**.
See the [LICENSE](LICENSE) file for details.

---

## 🤝 Contributors

* [SpookyKipper](https://github.com/SpookyKipper)
* [Deveroonie](https://github.com/Deveroonie)
* [MOFH Community](https://github.com/MOFHCommunity)


