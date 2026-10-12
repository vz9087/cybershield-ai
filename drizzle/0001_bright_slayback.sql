CREATE TABLE `awareness_attempts` (
	`id` int AUTO_INCREMENT NOT NULL,
	`userId` int NOT NULL,
	`score` int NOT NULL,
	`totalQuestions` int NOT NULL,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `awareness_attempts_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `email_outbox` (
	`id` int AUTO_INCREMENT NOT NULL,
	`recipient` varchar(320),
	`subject` varchar(240) NOT NULL,
	`status` varchar(40) NOT NULL DEFAULT 'provider_not_configured',
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `email_outbox_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `notifications` (
	`id` int AUTO_INCREMENT NOT NULL,
	`userId` int NOT NULL,
	`title` varchar(200) NOT NULL,
	`message` text NOT NULL,
	`type` varchar(40) NOT NULL DEFAULT 'info',
	`readStatus` int NOT NULL DEFAULT 0,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `notifications_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `scans` (
	`id` varchar(36) NOT NULL,
	`userId` int NOT NULL,
	`scanType` enum('url','email','sms','link','apk','api') NOT NULL,
	`inputReference` text NOT NULL,
	`riskScore` int NOT NULL,
	`riskLevel` varchar(32) NOT NULL,
	`threatType` varchar(100) NOT NULL,
	`reasons` text NOT NULL,
	`indicators` text NOT NULL,
	`recommendation` text NOT NULL,
	`safeAlternative` varchar(500),
	`fileHash` varchar(64),
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `scans_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `security_logs` (
	`id` int AUTO_INCREMENT NOT NULL,
	`userId` int,
	`action` varchar(120) NOT NULL,
	`status` varchar(40) NOT NULL DEFAULT 'success',
	`details` text,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `security_logs_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `threats` (
	`id` int AUTO_INCREMENT NOT NULL,
	`indicator` varchar(500) NOT NULL,
	`threatType` varchar(100) NOT NULL,
	`riskScore` int NOT NULL,
	`status` enum('confirmed','blocked','safe') NOT NULL DEFAULT 'confirmed',
	`source` varchar(100) NOT NULL DEFAULT 'community-report',
	`firstDetected` timestamp NOT NULL DEFAULT (now()),
	`lastChecked` timestamp NOT NULL DEFAULT (now()),
	`confirmedBy` varchar(320),
	`notes` text,
	CONSTRAINT `threats_id` PRIMARY KEY(`id`),
	CONSTRAINT `threats_indicator_unique` UNIQUE(`indicator`)
);
--> statement-breakpoint
CREATE TABLE `tickets` (
	`id` int AUTO_INCREMENT NOT NULL,
	`userId` int NOT NULL,
	`scanId` varchar(36),
	`category` varchar(100) NOT NULL,
	`description` text NOT NULL,
	`indicator` varchar(500),
	`priority` enum('low','medium','high','critical') NOT NULL DEFAULT 'medium',
	`status` enum('new','under_review','confirmed','false_report','need_more_info','resolved') NOT NULL DEFAULT 'new',
	`assignedAdminId` int,
	`adminNotes` text,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `tickets_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
ALTER TABLE `users` ADD `status` enum('active','suspended') DEFAULT 'active' NOT NULL;