PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE user (
	id INTEGER NOT NULL, 
	email VARCHAR(120) NOT NULL, 
	password_hash VARCHAR(256) NOT NULL, 
	role VARCHAR(20) NOT NULL, 
	created_at DATETIME NOT NULL, 
	PRIMARY KEY (id), 
	UNIQUE (email)
);
INSERT INTO user VALUES(1,'admin@pharmaevents.com','scrypt:32768:8:1$6BLiX8sM5EfdILM4$7556a3668b8e620b8f31e87f83e36e9b81c2676f24a4aa5ecf5cc807b01dcbced208a727c7f9fd147646ff4512d9c78a8a941218da2e8a49254c5073a60b19be','admin','2025-05-14 13:25:13.035530');
INSERT INTO user VALUES(2,'manager@pharmaevents.com','scrypt:32768:8:1$YqoOCan3O80S6UkJ$166b85d911b45dfa1a5d0787cbdd9adb1ae9c422c19240226795666956e5ef8cc8107d4ae29b045d7248eb3dac610e10ce7b69241e1d9e64024a2e8181ad8613','event_manager','2025-05-14 13:25:13.035534');
INSERT INTO user VALUES(3,'rep@pharmaevents.com','scrypt:32768:8:1$bMC04PIFvHEJcFDE$5aad48d2464bd59268cc075e1cdfb4d17cac63012dd8704eabd9a95e9bbda694eb826ef119358fa7dfdf1048b539f44963979a95aa62616c116b8c606d7909fd','medical_rep','2025-05-14 13:25:13.035534');
INSERT INTO user VALUES(4,'test@me.com','scrypt:32768:8:1$AiIHNAJBM2IPrjmJ$b570158c39b7e4cbfbfff2718dd2ee3b0cbfd398227aa6d703810e5090908ba7ccdb523a322c4de06ba7726daa9c5e1f6bd59d3cd62a00550e957a8d27d415e8','event_manager','2025-06-18 20:42:32.792034');
CREATE TABLE app_setting (
	id INTEGER NOT NULL, 
	"key" VARCHAR(50) NOT NULL, 
	value TEXT, 
	PRIMARY KEY (id), 
	UNIQUE ("key")
);
INSERT INTO app_setting VALUES(1,'theme','dark');
INSERT INTO app_setting VALUES(2,'app_name','PharmaEvents');
CREATE TABLE event_category (
	id INTEGER NOT NULL, 
	name VARCHAR(50) NOT NULL, 
	PRIMARY KEY (id), 
	UNIQUE (name)
);
INSERT INTO event_category VALUES(1,'Cardiology');
INSERT INTO event_category VALUES(2,'Oncology');
INSERT INTO event_category VALUES(3,'Neurology');
INSERT INTO event_category VALUES(4,'Pediatrics');
INSERT INTO event_category VALUES(5,'Endocrinology');
INSERT INTO event_category VALUES(6,'Dermatology');
INSERT INTO event_category VALUES(7,'Psychiatry');
INSERT INTO event_category VALUES(8,'Product Launch');
INSERT INTO event_category VALUES(9,'Medical Education');
INSERT INTO event_category VALUES(10,'Patient Awareness');
INSERT INTO event_category VALUES(11,'Internal Training');
CREATE TABLE event_type (
	id INTEGER NOT NULL, 
	name VARCHAR(50) NOT NULL, 
	PRIMARY KEY (id), 
	UNIQUE (name)
);
INSERT INTO event_type VALUES(1,'Conference');
INSERT INTO event_type VALUES(2,'Webinar');
INSERT INTO event_type VALUES(3,'Workshop');
INSERT INTO event_type VALUES(4,'Symposium');
INSERT INTO event_type VALUES(5,'Roundtable Meeting');
INSERT INTO event_type VALUES(6,'Investigator Meeting');
CREATE TABLE venue (
	id INTEGER NOT NULL, 
	name VARCHAR(100) NOT NULL, 
	governorate VARCHAR(50) NOT NULL, 
	PRIMARY KEY (id)
);
INSERT INTO venue VALUES(1,'Nile Conference Hall','Cairo');
INSERT INTO venue VALUES(2,'Alexandria Medical Center','Alexandria');
INSERT INTO venue VALUES(3,'Luxor International Conference Center','Luxor');
INSERT INTO venue VALUES(4,'Children''s Hospital Auditorium','Alexandria');
INSERT INTO venue VALUES(5,'Mansoura University Hospital','Dakahlia');
CREATE TABLE service_request (
	id INTEGER NOT NULL, 
	name VARCHAR(100) NOT NULL, 
	PRIMARY KEY (id), 
	UNIQUE (name)
);
INSERT INTO service_request VALUES(1,'Clinical Trial Support');
INSERT INTO service_request VALUES(2,'Product Education');
INSERT INTO service_request VALUES(3,'Physician Training');
CREATE TABLE employee_code (
	id INTEGER NOT NULL, 
	code VARCHAR(20) NOT NULL, 
	name VARCHAR(100) NOT NULL, 
	PRIMARY KEY (id), 
	UNIQUE (code)
);
INSERT INTO employee_code VALUES(1,'EMP001','John Doe');
INSERT INTO employee_code VALUES(2,'EMP002','Jane Smith');
INSERT INTO employee_code VALUES(3,'EMP003','Ahmed Hassan');
CREATE TABLE event (
	id INTEGER NOT NULL, 
	name VARCHAR(100) NOT NULL, 
	requester_name VARCHAR(100) NOT NULL, 
	is_online BOOLEAN, 
	image_url VARCHAR(255), 
	image_file VARCHAR(255), 
	start_datetime DATETIME NOT NULL, 
	end_datetime DATETIME NOT NULL, 
	registration_deadline DATETIME NOT NULL, 
	governorate VARCHAR(50), 
	venue_id INTEGER, 
	service_request_id INTEGER, 
	employee_code_id INTEGER, 
	event_type_id INTEGER NOT NULL, 
	description TEXT, 
	created_at DATETIME NOT NULL, 
	user_id INTEGER NOT NULL, 
	status VARCHAR(20) NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(venue_id) REFERENCES venue (id), 
	FOREIGN KEY(service_request_id) REFERENCES service_request (id), 
	FOREIGN KEY(employee_code_id) REFERENCES employee_code (id), 
	FOREIGN KEY(event_type_id) REFERENCES event_type (id), 
	FOREIGN KEY(user_id) REFERENCES user (id)
);
INSERT INTO event VALUES(1,'test','test',0,NULL,NULL,'2025-06-24 00:37:00.000000','2025-07-01 12:40:00.000000','2025-06-21 10:38:00.000000','',NULL,NULL,NULL,4,'test','2025-06-21 09:38:40.324777',4,'pending');
CREATE TABLE event_categories (
	event_id INTEGER NOT NULL, 
	category_id INTEGER NOT NULL, 
	PRIMARY KEY (event_id, category_id), 
	FOREIGN KEY(event_id) REFERENCES event (id), 
	FOREIGN KEY(category_id) REFERENCES event_category (id)
);
INSERT INTO event_categories VALUES(1,5);
COMMIT;
