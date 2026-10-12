CREATE TABLE `local_credentials` (
	`id` int AUTO_INCREMENT NOT NULL,
	`userId` int NOT NULL,
	`email` varchar(320) NOT NULL,
	`passwordHash` varchar(255) NOT NULL,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `local_credentials_id` PRIMARY KEY(`id`),
	CONSTRAINT `local_credentials_user_unique` UNIQUE(`userId`),
	CONSTRAINT `local_credentials_email_unique` UNIQUE(`email`)
);
--> statement-breakpoint
ALTER TABLE `local_credentials` ADD CONSTRAINT `local_credentials_userId_users_id_fk` FOREIGN KEY (`userId`) REFERENCES `users`(`id`) ON DELETE cascade ON UPDATE no action;