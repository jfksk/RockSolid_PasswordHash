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

class RockSolid_PasswordHash_Model_Admin_User
    extends Mage_Admin_Model_User
{
    /**
     * Authenticate user name and password and save loaded record
     *
     * @param string $username
     * @param string $password
     * @return boolean
     * @throws Mage_Core_Exception
     */
    public function authenticate($username, $password)
    {
        $config = Mage::getStoreConfigFlag('admin/security/use_case_sensitive_login');
        $result = false;

        try {
            Mage::dispatchEvent('admin_user_authenticate_before', array(
                'username' => $username,
                'user'     => $this
            ));
            $this->loadByUsername($username);
            $sensitive = ($config) ? $username == $this->getUsername() : true;

            if (Mage::helper('Core')->validateHash($password, $this->getPassword()) && $sensitive && $this->getId()) {
                if ($this->getIsActive() != '1') {
                    Mage::throwException(Mage::helper('adminhtml')->__('This account is inactive.'));
                }
                if (!$this->hasAssigned2Role($this->getId())) {
                    Mage::throwException(Mage::helper('adminhtml')->__('Access denied.'));
                }
                $result = true;
            }

            Mage::dispatchEvent('admin_user_authenticate_after', array(
                'username' => $username,
                'password' => $password,
                'user'     => $this,
                'result'   => $result,
            ));
        } catch (Mage_Core_Exception $e) {
            $this->unsetData();
            throw $e;
        }

        if (!$result) {
            $this->unsetData();
        }
        return $result;
    }

    /**
     * Retrieve encoded password
     *
     * @param string $password
     * @return string
     */
    protected function _getEncodedPassword($password)
    {
        return $this->_getHelper('Core')->getEncryptor()->getHashPassword($password);
    }
}
