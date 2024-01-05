DROP DATABASE IF EXISTS `WebfkillerFuzzer2`;
CREATE DATABASE `WebfkillerFuzzer2`;
USE `WebfkillerFuzzer2`;

DROP TABLE IF EXISTS `ProxyRequest`;
CREATE TABLE `ProxyRequest` (
    `no` INT AUTO_INCREMENT PRIMARY KEY,
    `method` VARCHAR(255),
    `URL` TEXT,
    `header` TEXT,
    `Parms` TEXT
);

DROP TABLE IF EXISTS `ProxyResponse`;
CREATE TABLE `ProxyResponse` (
    `no` INT AUTO_INCREMENT PRIMARY KEY,
    `URL` TEXT,
    `status_code` INT,
    `header` TEXT,
    `body` TEXT
);

DROP TABLE IF EXISTS `ModifiedPacketComposerRequest`;
CREATE TABLE `ModifiedPacketComposerRequest` (
    `no` INT AUTO_INCREMENT PRIMARY KEY,
    `type` VARCHAR(255),
    `status_code` INT,
    `TIME` INT,
    `URL` TEXT,
    `header` TEXT,
    `randomhash` VARCHAR(255),
    `parms` TEXT,
    `parms_count` INT,
    `body_size` INT,
    `body` TEXT
);

DROP TABLE IF EXISTS `ModifiedPacketComposerSelenium`;
CREATE TABLE `ModifiedPacketComposerSelenium` (
    `no` INT AUTO_INCREMENT PRIMARY KEY,
    `URL` TEXT,
    `randomhash` VARCHAR(255),
    `parms` TEXT,
    `parms_count` INT,
    `body` TEXT
);

DROP TABLE IF EXISTS `ScannerResult`;
CREATE TABLE `ScannerResult` (
    `no` INT AUTO_INCREMENT PRIMARY KEY,
    `type` VARCHAR(255),
    `URL` TEXT,
    `parms` TEXT
);
