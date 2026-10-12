ALTER TABLE `email_outbox` ADD `body` text;--> statement-breakpoint
ALTER TABLE `scans` ADD `action` varchar(32) DEFAULT 'allow' NOT NULL;--> statement-breakpoint
ALTER TABLE `tickets` ADD `additionalDetails` text;--> statement-breakpoint
ALTER TABLE `tickets` ADD `riskScore` int;--> statement-breakpoint
ALTER TABLE `tickets` ADD `threatType` varchar(100);--> statement-breakpoint
ALTER TABLE `tickets` ADD `screenshotData` mediumtext;