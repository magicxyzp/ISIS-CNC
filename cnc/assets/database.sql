SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";

CREATE TABLE `logs` (
  `id` int(11) NOT NULL,
  `username` varchar(255) NOT NULL,
  `host` varchar(255) NOT NULL,
  `port` int(11) NOT NULL,
  `duration` int(11) NOT NULL,
  `method` varchar(255) NOT NULL,
  `time_sent` int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE `users` (
  `id` int(11) NOT NULL,
  `username` varchar(255) NOT NULL,
  `password` varchar(255) NOT NULL,
  `vip` int(1) NOT NULL,
  `reseller` int(1) NOT NULL,
  `mod` int(1) NOT NULL,
  `admin` int(1) NOT NULL,
  `bypass_powersaving` int(1) NOT NULL,
  `bypass_blacklist` int(1) NOT NULL,
  `bypass_softmaxtime` int(1) NOT NULL,
  `api_access` int(1) NOT NULL DEFAULT 0,
  `theme` varchar(255) NOT NULL,
  `max_time` int(11) NOT NULL,
  `concurrents` int(11) NOT NULL,
  `banned` int(1) NOT NULL,
  `locked` int(1) NOT NULL,
  `time_created` int(11) NOT NULL,
  `created_by` varchar(255) NOT NULL,
  `expire` int(11) NOT NULL,
  `must_change_password` int(1) NOT NULL DEFAULT 0,
  `mfa_enabled` int(1) NOT NULL DEFAULT 0,
  `mfa_secret` varchar(64) NOT NULL DEFAULT ''
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO `users` (`id`, `username`, `password`, `vip`, `reseller`, `mod`, `admin`, `bypass_powersaving`, `bypass_blacklist`, `bypass_softmaxtime`, `api_access`, `theme`, `max_time`, `concurrents`, `banned`, `locked`, `time_created`, `created_by`, `expire`, `must_change_password`, `mfa_enabled`, `mfa_secret`) VALUES
(1, 'root', '057ba03d6c44104863dc7361fe4578965d1887360f90a0895882e58a6248fc86', 1, 1, 1, 1, 1, 1, 1, 1, 'default', 9999, 9999, 0, 0, 1725997930, 'system', 0, 0, 0, '');

ALTER TABLE `logs`
  ADD PRIMARY KEY (`id`);

ALTER TABLE `users`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `username` (`username`);

ALTER TABLE `logs`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=1;

ALTER TABLE `users`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

-- Existing installs: run once if upgrading:
-- ALTER TABLE `users` ADD COLUMN `must_change_password` int(1) NOT NULL DEFAULT 0 AFTER `expire`;
-- ALTER TABLE `users` ADD COLUMN `mfa_enabled` int(1) NOT NULL DEFAULT 0 AFTER `must_change_password`;
-- ALTER TABLE `users` ADD COLUMN `mfa_secret` varchar(64) NOT NULL DEFAULT '' AFTER `mfa_enabled`;
COMMIT;
