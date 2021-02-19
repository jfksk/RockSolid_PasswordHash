# RockSolid_PasswordHash

Password hash upgrade to strong algorithms.

*Features:*

- Auto upgrade of password and api key hashes
- Hashing algo is auto determined by PHP's password_hash function

Same as: [OpenMage PR 998](https://github.com/OpenMage/magento-lts/pull/998)

## Requirements
* PHP >= 7.0
* OpenMage >= 19


## Compatibility

This module is compatible with all hashing algos (md5,sha256, sha512, bcrypt) previously used in Magento

*Overwrites*: 

- Mage_Admin_Model_User
- Mage_Api_Model_User
- Mage_Customer_Model_Customer

*Reconfigurations:*

- config/global/helpers/core/encryption_model

*Changed events:*

- admin_user_login
- customer_upgrade_password

## Security

If you discover any security related issues, please email hallo@rocksolid.at instead of using the issue tracker.


## Support
If you encounter any problems or bugs, please create an issue on GitHub.

There is, however, commercial support available. Inquiries: rocksolid.at


## Licence
[GNU General Public License, version 3 (GPLv3)](http://opensource.org/licenses/gpl-3.0)


## Copyright
(c) 2021 Jan F. Kousek (rocksolid.at)
