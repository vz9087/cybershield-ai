CREATE TABLE `ticket_responses` (
	`id` int AUTO_INCREMENT NOT NULL,
	`ticketId` int NOT NULL,
	`authorId` int NOT NULL,
	`authorRole` enum('user','admin') NOT NULL,
	`message` text NOT NULL,
	`attachmentName` varchar(255),
	`attachmentType` varchar(100),
	`attachmentData` mediumtext,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `ticket_responses_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
ALTER TABLE `users` MODIFY COLUMN `publicId` varchar(16) NOT NULL;