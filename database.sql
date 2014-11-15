DROP TABLE IF EXISTS `pastes`;

CREATE TABLE `pastes` (
  `token` varchar(128) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `data` text CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `time` int(11) DEFAULT NULL,
  `jscrypt`  tinyint(1) NOT NULL DEFAULT 0,
  `burnread` tinyint(1) NOT NULL DEFAULT 0,
  `inserted` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `ipaddress` varchar(64) CHARACTER SET utf8 COLLATE utf8_bin DEFAULT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

ALTER TABLE `pastes`
 ADD PRIMARY KEY (`token`), ADD KEY `itime` (`time`);

DROP TABLE IF EXISTS `retrieves`;

CREATE TABLE `retrieves` (
  `time` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `id` int NOT NULL auto_increment,
  `token` varchar(128) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `ipaddress` varchar(64) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  PRIMARY KEY (`time` DESC, `id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;
