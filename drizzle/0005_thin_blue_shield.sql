CREATE TABLE `password_reset_otps` (
	`id` int AUTO_INCREMENT NOT NULL,
	`userId` int NOT NULL,
	`email` varchar(320) NOT NULL,
	`otpHash` varchar(255) NOT NULL,
	`expiresAt` timestamp NOT NULL,
	`consumedAt` timestamp NULL DEFAULT NULL,
	`attemptCount` int NOT NULL DEFAULT 0,
	`createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	CONSTRAINT `password_reset_otps_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `password_reset_throttle` (
	`id` int AUTO_INCREMENT NOT NULL,
	`email` varchar(320) NOT NULL,
	`requestedAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`type` varchar(40) NOT NULL DEFAULT 'request',
	CONSTRAINT `password_reset_throttle_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
ALTER TABLE `users` ADD `sessionsInvalidatedAt` timestamp NULL DEFAULT NULL;