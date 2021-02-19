<?php
/**
 * This file is part of a RockSolid e.U. Module.
 *
 * This RockSolid e.U. Module is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This RockSolid e.U. Module is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * @category  RockSolid
 * @package   RockSolid_PageCache
 * @author    Jan F. Kousek <jan@rocksolid.at>
 * @copyright 2021 RockSolid e.U. | Jan F. Kousek (http://www.rocksolid.at)
 * @license   http://opensource.org/licenses/gpl-3.0 GNU General Public License, version 3 (GPLv3)
 */

class RockSolid_PasswordHash_Model_Core_Encryption
    extends Mage_Core_Model_Encryption
{
    /**
     * Generate a [salted] hash.
     *
     * $salt can be:
     * false - no salt will be used
     * integer - a random with specified length will be generated
     *
     * @param string $password
     * @param mixed $salt
     * @return bool|string
     */
    public function getHash($password, $salt = false)
    {
        if (is_integer($salt)) {
            $salt = $this->_helper->getRandomString($salt);
        }
        return $salt === false
            ? $this->hash($password, self::HASH_VERSION_SHA256)
            : $this->hash($salt . $password, self::HASH_VERSION_SHA256) . ':' . $salt;
    }

    /**
     * Generate hash for a password
     *
     * @param string $password
     * @param mixed $salt deprecated
     * @return bool|string
     */
    public function getHashPassword($password, $salt = null)
    {
        return $this->hash($password, self::HASH_VERSION_LATEST);
    }

    /**
     * Check if a given hash should be upgraded
     *
     * @param string $hash
     * @return bool
     */
    public function passwordHashNeedsUpgrade($hash)
    {
        // all old hashes MD5/SHA256/SHA512 with salt. password_hash hashes start w/ $
        if (isset($hash[0]) && $hash[0] != '$') {
            return true;
        }

        return password_needs_rehash($hash, PASSWORD_DEFAULT);
    }

    /**
     * Hash a string
     *
     * @param string $data
     * @param int $version
     * @return bool|string
     */
    public function hash($data, $version = self::HASH_VERSION_MD5)
    {
        if (self::HASH_VERSION_LATEST === $version) {
            return password_hash($data, PASSWORD_DEFAULT);
        } elseif (self::HASH_VERSION_SHA256 == $version) {
            return hash('sha256', $data);
        } elseif (self::HASH_VERSION_SHA512 == $version) {
            return hash('sha512', $data);
        }
        return md5($data);
    }

    /**
     * Validate hash against hashing method (with or without salt)
     *
     * @param string $password
     * @param string $hash
     * @return bool
     */
    public function validateHash($password, $hash)
    {
        // password_hash hashes start w/ $
        if (isset($hash[0]) && $hash[0] == '$') {
            return $this->validateHashByVersion($password, $hash, self::HASH_VERSION_LATEST);
        }

        $result = $this->validateHashByVersion($password, $hash, self::HASH_VERSION_SHA512)
            || $this->validateHashByVersion($password, $hash, self::HASH_VERSION_SHA256)
            || $this->validateHashByVersion($password, $hash, self::HASH_VERSION_MD5);

        if (!$result) {
            $this->hash($password, self::HASH_VERSION_LATEST);
        }

        return $result;
    }

    /**
     * Validate hash by specified version
     *
     * @param string $password
     * @param string $hash
     * @param int $version
     * @return bool
     */
    public function validateHashByVersion($password, $hash, $version = self::HASH_VERSION_MD5)
    {
        if ($version == self::HASH_VERSION_LATEST) {
            return password_verify($password, $hash);
        }
        // look for salt
        $hashArr = explode(':', $hash, 2);
        if (1 === count($hashArr)) {
            return hash_equals($this->hash($password, $version), $hash);
        }
        list($hash, $salt) = $hashArr;
        return hash_equals($this->hash($salt . $password, $version), $hash);
    }
}
