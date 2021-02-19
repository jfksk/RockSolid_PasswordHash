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

class RockSolid_PasswordHash_Model_Observer
{
    /**
     * Validate admin password and upgrade hash version
     *
     * @param Varien_Event_Observer $observer
     */
    public function actionAdminAuthenticate($observer)
    {
        $password = $observer->getEvent()->getPassword();
        $user = $observer->getEvent()->getUser();
        $authResult = $observer->getEvent()->getResult();

        if (!$authResult) {
            return;
        }

        if((bool)$user->getPasswordUpgraded()) {
            return;
        }

        $encryptor = Mage::helper('Core')->getEncryptor();
        if ($encryptor->passwordHashNeedsUpgrade($user->getPassword())) {
            $user->setNewPassword($password)
                ->setForceNewPassword(true)
                ->save();
            $user->setPasswordUpgraded(true);
        }
    }

    /**
     * Upgrade the hash version, if needed
     *
     * @param Varien_Event_Observer $observer
     */
    public function apiAuthenticated($observer)
    {
        $encryptor = Mage::helper('Core')->getEncryptor();

        /* @var $user Mage_Api_Model_User */
        $user = $observer->getModel();
        if ($encryptor->passwordHashNeedsUpgrade($user->getApiKey())) {
            $user->setApiKey($observer->getApiKey())->save();
        }
    }

    /**
     * Upgrade customer password hash when customer has logged in
     *
     * @param Varien_Event_Observer $observer
     */
    public function actionUpgradeCustomerPassword($observer)
    {
        $password = $observer->getEvent()->getPassword();
        $model = $observer->getEvent()->getModel();

        $encryptor = Mage::helper('Core')->getEncryptor();
        if ($encryptor->passwordHashNeedsUpgrade($model->getPasswordHash())) {
            $model->changePassword($password);
        }
    }
}
