DROP TABLE IF EXISTS `pastes`;

CREATE TABLE `pastes` (
  `token` varchar(128) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `data` text CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `time` int(11) DEFAULT NULL,
  `jscrypt` tinyint(1) NOT NULL,
  `inserted` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


ALTER TABLE `pastes`
 ADD PRIMARY KEY (`token`), ADD KEY `itime` (`time`);
