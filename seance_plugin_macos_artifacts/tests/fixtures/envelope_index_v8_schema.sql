CREATE TABLE messages (
    ROWID INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id INTEGER NOT NULL DEFAULT 0,
    document_id BLOB,
    remote_id INTEGER,
    global_message_id INTEGER NOT NULL REFERENCES message_global_data(ROWID) ON DELETE CASCADE,
    sender INTEGER,
    subject_prefix,
    subject INTEGER,
    date_sent INTEGER,
    date_received INTEGER,
    date_last_viewed INTEGER,
    mailbox INTEGER,
    remote_mailbox INTEGER,
    flags INTEGER,
    read,
    flagged,
    size INTEGER,
    color,
    type INTEGER,
    conversation_id INTEGER DEFAULT -1,
    snippet TEXT DEFAULT NULL,
    fuzzy_ancestor INTEGER DEFAULT NULL,
    automated_conversation INTEGER DEFAULT 0,
    root_status INTEGER DEFAULT -1,
    conversation_position INTEGER DEFAULT -1,
    deleted INTEGER DEFAULT 0,
    list_id_hash INTEGER NOT NULL DEFAULT 0,
    searchable_message INTEGER REFERENCES searchable_messages(message_id) ON DELETE SET NULL
);
CREATE INDEX date_index ON messages(date_received);
CREATE INDEX date_last_viewed_index ON messages(date_last_viewed);
CREATE INDEX message_message_id_mailbox_index ON messages(message_id, mailbox);
CREATE INDEX message_global_message_id_mailbox_index ON messages(global_message_id, mailbox);
CREATE INDEX message_document_id_index ON messages(document_id);
CREATE INDEX message_read_index ON messages(read);
CREATE INDEX message_flagged_index ON messages(flagged);
CREATE INDEX message_mailbox_index ON messages(mailbox, date_received);
CREATE INDEX message_remote_mailbox_index ON messages(remote_mailbox, remote_id);
CREATE INDEX message_type_index ON messages(type);
CREATE INDEX message_conversation_id_conversation_position_index ON messages(conversation_id, conversation_position);
CREATE INDEX message_fuzzy_ancestor_index ON messages(fuzzy_ancestor);
CREATE INDEX message_subject_fuzzy_ancestor_index ON messages(subject, fuzzy_ancestor);
CREATE INDEX message_sender_subject_automated_conversation_index ON messages(sender, subject, automated_conversation);
CREATE INDEX message_sender_index ON messages(sender);
CREATE INDEX message_root_status ON messages(root_status);
CREATE INDEX message_deleted_mailbox_index ON messages(deleted, mailbox);
CREATE INDEX message_deleted_index ON messages(deleted);
CREATE INDEX message_list_id_hash_index ON messages(list_id_hash);
CREATE INDEX messages_searchable_message_deleted_index ON messages(searchable_message, deleted);
CREATE TABLE subjects (ROWID INTEGER PRIMARY KEY, subject COLLATE RTRIM, normalized_subject COLLATE RTRIM);
CREATE INDEX subject_subject_index ON subjects(subject);
CREATE INDEX subject_normalized_subject_index ON subjects(normalized_subject);
CREATE TABLE addresses (ROWID INTEGER PRIMARY KEY, address COLLATE NOCASE, comment, UNIQUE(address, comment));
CREATE INDEX addresses_address_index ON addresses(address);
CREATE TABLE mailboxes (ROWID INTEGER PRIMARY KEY AUTOINCREMENT, url UNIQUE, total_count INTEGER DEFAULT 0, unread_count INTEGER DEFAULT 0, unseen_count INTEGER DEFAULT 0, deleted_count INTEGER DEFAULT 0, unread_count_adjusted_for_duplicates INTEGER DEFAULT 0, change_identifier, source INTEGER, alleged_change_identifier);
CREATE INDEX mailboxes_source_index ON mailboxes(source);
CREATE TABLE ews_folders (ROWID INTEGER PRIMARY KEY, folder_id TEXT UNIQUE ON CONFLICT REPLACE, mailbox_id INTEGER NOT NULL UNIQUE ON CONFLICT REPLACE REFERENCES mailboxes(ROWID) ON DELETE CASCADE, sync_state TEXT);
CREATE INDEX ews_folders_mailbox_id_index ON ews_folders(mailbox_id);
CREATE TABLE duplicates_unread_count (ROWID INTEGER PRIMARY KEY, message_id INTEGER NOT NULL, mailbox_id INTEGER NOT NULL REFERENCES mailboxes(ROWID) ON DELETE CASCADE, unread_count INTEGER DEFAULT 0, UNIQUE(message_id, mailbox_id));
CREATE INDEX duplicates_unread_count_mailbox_id_index ON duplicates_unread_count(mailbox_id);
CREATE TABLE events (ROWID INTEGER PRIMARY KEY AUTOINCREMENT, message_id INTEGER NOT NULL REFERENCES messages(ROWID) ON DELETE CASCADE, start_date INTEGER, end_date INTEGER, location TEXT, out_of_date INTEGER DEFAULT 0, processed INTEGER DEFAULT 0, is_all_day INTEGER DEFAULT 0, associated_id_string TEXT, original_receiving_account TEXT, ical_uid TEXT, is_response_requested INTEGER DEFAULT 0);
CREATE INDEX events_message_id_index ON events(message_id);
CREATE TABLE labels (message_id INTEGER REFERENCES messages(ROWID) ON DELETE CASCADE, mailbox_id INTEGER REFERENCES mailboxes(ROWID) ON DELETE CASCADE, PRIMARY KEY(message_id, mailbox_id)) WITHOUT ROWID;
CREATE INDEX labels_mailbox_id_index on labels(mailbox_id);
CREATE TABLE mailbox_actions (ROWID INTEGER PRIMARY KEY AUTOINCREMENT, account_identifier TEXT, action_type INTEGER, mailbox_name TEXT);
CREATE INDEX mailbox_actions_action_type_index ON mailbox_actions(action_type);
CREATE TABLE last_spotlight_check_date (message_id INTEGER NOT NULL UNIQUE ON CONFLICT REPLACE REFERENCES messages(ROWID) ON DELETE CASCADE, date INTEGER, PRIMARY KEY(message_id)) WITHOUT ROWID;
CREATE INDEX last_spotlight_check_date_message_id_date_index ON last_spotlight_check_date(message_id, date);
CREATE TRIGGER before_delete_message BEFORE DELETE ON messages
BEGIN
UPDATE duplicates_unread_count SET unread_count = unread_count - 1 WHERE (OLD.message_id != 0 AND duplicates_unread_count.message_id = OLD.message_id AND duplicates_unread_count.mailbox_id = OLD.mailbox) AND (OLD.flags&1 = 0 AND OLD.flags&2 = 0);
UPDATE mailboxes SET unread_count_adjusted_for_duplicates = MAX(MIN(1, unread_count), unread_count_adjusted_for_duplicates - 1) WHERE ((mailboxes.ROWID = OLD.mailbox AND mailboxes.source ISNULL AND OLD.message_id = 0) OR (mailboxes.source NOTNULL AND mailboxes.ROWID IN (SELECT mailbox_id FROM labels WHERE message_id = OLD.ROWID) AND ((mailboxes.source = OLD.mailbox AND OLD.message_id = 0) OR ((SELECT count() FROM labels WHERE message_id IN (SELECT ROWID FROM messages WHERE message_id = OLD.message_id) AND mailbox_id = mailboxes.ROWID) = 0 AND OLD.message_id != 0)))) AND (OLD.flags&1 = 0 AND OLD.flags&2 = 0);

UPDATE mailboxes SET unread_count = MAX(0, unread_count - 1), unread_count_adjusted_for_duplicates = MIN(unread_count_adjusted_for_duplicates, unread_count - 1) WHERE ((mailboxes.ROWID = OLD.mailbox AND mailboxes.source ISNULL) OR (mailboxes.ROWID IN (SELECT mailbox_id FROM labels WHERE message_id = OLD.ROWID) AND mailboxes.source = OLD.mailbox)) AND (OLD.flags&1 = 0 AND OLD.flags&2 = 0);

UPDATE mailboxes SET total_count = MAX(0, total_count - 1) WHERE (mailboxes.ROWID = OLD.mailbox AND mailboxes.source ISNULL) OR (mailboxes.ROWID IN (SELECT mailbox_id FROM labels WHERE message_id = OLD.ROWID) AND mailboxes.source = OLD.mailbox);
UPDATE mailboxes SET unseen_count = MAX(0, unseen_count - 1) WHERE (mailboxes.ROWID = OLD.mailbox AND mailboxes.source ISNULL AND OLD.flags&1 = 0) OR (mailboxes.ROWID IN (SELECT mailbox_id FROM labels WHERE message_id = OLD.ROWID) AND mailboxes.source = OLD.mailbox AND OLD.flags&1 = 0);
UPDATE mailboxes SET deleted_count = MAX(0, deleted_count - 1) WHERE (mailboxes.ROWID = OLD.mailbox AND mailboxes.source ISNULL AND OLD.flags&2 != 0) OR (mailboxes.ROWID IN (SELECT mailbox_id FROM labels WHERE message_id = OLD.ROWID) AND mailboxes.source = OLD.mailbox AND OLD.flags&2 != 0);
END;
CREATE TRIGGER after_delete_message AFTER DELETE ON messages
BEGIN
DELETE FROM subjects WHERE ROWID = OLD.subject AND (SELECT COUNT() FROM messages WHERE subject = OLD.subject LIMIT 1) = 0;
DELETE FROM message_global_data WHERE ROWID = OLD.global_message_id AND (SELECT COUNT() FROM messages WHERE global_message_id = OLD.global_message_id LIMIT 1) = 0;
DELETE FROM addresses WHERE ROWID = OLD.sender AND ((SELECT COUNT() FROM messages WHERE sender = OLD.sender LIMIT 1) = 0) AND ((SELECT COUNT() FROM recipients WHERE address_id = OLD.sender LIMIT 1) = 0);

UPDATE messages SET fuzzy_ancestor = -1 WHERE messages.fuzzy_ancestor = OLD.ROWID;
END;
CREATE TRIGGER after_insert_message AFTER INSERT ON messages
BEGIN
UPDATE mailboxes SET total_count = total_count + 1 WHERE (mailboxes.ROWID = NEW.mailbox AND mailboxes.source ISNULL) OR (mailboxes.ROWID IN (SELECT mailbox_id FROM labels WHERE message_id = NEW.ROWID) AND mailboxes.source = NEW.mailbox);
UPDATE mailboxes SET unseen_count = unseen_count + 1 WHERE ((mailboxes.ROWID = NEW.mailbox AND mailboxes.source ISNULL) OR (mailboxes.ROWID IN (SELECT mailbox_id FROM labels WHERE message_id = NEW.ROWID) AND mailboxes.source = NEW.mailbox)) AND NEW.flags&1 = 0;
UPDATE mailboxes SET deleted_count = deleted_count + 1 WHERE ((mailboxes.ROWID = NEW.mailbox AND mailboxes.source ISNULL) OR (mailboxes.ROWID IN (SELECT mailbox_id FROM labels WHERE message_id = NEW.ROWID) AND mailboxes.source = NEW.mailbox)) AND NEW.flags&2 != 0;
END;
CREATE TRIGGER after_insert_message_unread AFTER INSERT ON messages WHEN (NEW.flags&1 = 0 AND NEW.flags&2 = 0)
BEGIN
UPDATE mailboxes SET unread_count = unread_count + 1 WHERE (mailboxes.ROWID = NEW.mailbox AND mailboxes.source ISNULL) OR (mailboxes.ROWID IN (SELECT mailbox_id FROM labels WHERE message_id = NEW.ROWID) AND mailboxes.source = NEW.mailbox);

INSERT OR IGNORE INTO duplicates_unread_count (message_id, mailbox_id) VALUES (NULLIF(NEW.message_id, 0), NEW.mailbox);
UPDATE duplicates_unread_count SET unread_count = unread_count + 1 WHERE NEW.message_id != 0 AND duplicates_unread_count.message_id = NEW.message_id AND duplicates_unread_count.mailbox_id = NEW.mailbox;
UPDATE mailboxes SET unread_count_adjusted_for_duplicates = MIN(unread_count_adjusted_for_duplicates + 1, unread_count) WHERE ((mailboxes.ROWID = NEW.mailbox AND mailboxes.source ISNULL) OR (mailboxes.ROWID IN (SELECT mailbox_id FROM labels WHERE message_id = NEW.ROWID) AND mailboxes.source = NEW.mailbox)) AND NEW.message_id = 0;
END;
CREATE TRIGGER after_update_message AFTER UPDATE OF flags ON messages
BEGIN
UPDATE mailboxes SET unseen_count = MAX(0, unseen_count - 1) WHERE ((mailboxes.ROWID = NEW.mailbox AND mailboxes.source ISNULL) OR (mailboxes.ROWID IN (SELECT mailbox_id FROM labels WHERE message_id = NEW.ROWID) AND mailboxes.source = NEW.mailbox)) AND OLD.flags&1 = 0 AND NEW.flags&1 != 0;
UPDATE mailboxes SET deleted_count = MAX(0, deleted_count - 1) WHERE ((mailboxes.ROWID = NEW.mailbox AND mailboxes.source ISNULL) OR (mailboxes.ROWID IN (SELECT mailbox_id FROM labels WHERE message_id = NEW.ROWID) AND mailboxes.source = NEW.mailbox)) AND OLD.flags&2 != 0 AND NEW.flags&2 = 0;

UPDATE mailboxes SET unseen_count = unseen_count + 1 WHERE ((mailboxes.ROWID = NEW.mailbox AND mailboxes.source ISNULL) OR (mailboxes.ROWID IN (SELECT mailbox_id FROM labels WHERE message_id = NEW.ROWID) AND mailboxes.source = NEW.mailbox)) AND OLD.flags&1 != 0 AND NEW.flags&1 = 0;
UPDATE mailboxes SET deleted_count = deleted_count + 1 WHERE ((mailboxes.ROWID = NEW.mailbox AND mailboxes.source ISNULL) OR (mailboxes.ROWID IN (SELECT mailbox_id FROM labels WHERE message_id = NEW.ROWID) AND mailboxes.source = NEW.mailbox)) AND OLD.flags&2 = 0 AND NEW.flags&2 != 0;
END;
CREATE TRIGGER after_update_message_becoming_read AFTER UPDATE OF flags ON messages WHEN (OLD.flags&1 = 0 AND OLD.flags&2 = 0) AND (NEW.flags&1 != 0 OR NEW.flags&2 != 0)
BEGIN
UPDATE duplicates_unread_count SET unread_count = unread_count - 1 WHERE OLD.message_id != 0 AND duplicates_unread_count.message_id = OLD.message_id AND duplicates_unread_count.mailbox_id = OLD.mailbox;
UPDATE mailboxes SET unread_count_adjusted_for_duplicates = MAX(MIN(1, unread_count), unread_count_adjusted_for_duplicates - 1) WHERE ((mailboxes.ROWID = OLD.mailbox AND mailboxes.source ISNULL) OR (mailboxes.ROWID IN (SELECT mailbox_id FROM labels WHERE message_id = OLD.ROWID) AND mailboxes.source = OLD.mailbox)) AND OLD.message_id = 0;

UPDATE mailboxes SET unread_count = MAX(0, unread_count - 1), unread_count_adjusted_for_duplicates = MIN(unread_count_adjusted_for_duplicates, unread_count - 1) WHERE (mailboxes.ROWID = NEW.mailbox AND mailboxes.source ISNULL) OR (mailboxes.ROWID IN (SELECT mailbox_id FROM labels WHERE message_id = NEW.ROWID) AND mailboxes.source = NEW.mailbox);
END;
CREATE TRIGGER after_update_message_becoming_unread AFTER UPDATE OF flags ON messages WHEN (OLD.flags&1 != 0 OR OLD.flags&2 != 0) AND (NEW.flags&1 = 0 AND NEW.flags&2 = 0)
BEGIN
UPDATE mailboxes SET unread_count = unread_count + 1 WHERE (mailboxes.ROWID = NEW.mailbox AND mailboxes.source ISNULL) OR (mailboxes.ROWID IN (SELECT mailbox_id FROM labels WHERE message_id = NEW.ROWID) AND mailboxes.source = NEW.mailbox);

INSERT OR IGNORE INTO duplicates_unread_count (message_id, mailbox_id) VALUES (NULLIF(NEW.message_id, 0), NEW.mailbox);
UPDATE duplicates_unread_count SET unread_count = unread_count + 1 WHERE NEW.message_id != 0 AND duplicates_unread_count.message_id = NEW.message_id AND duplicates_unread_count.mailbox_id = NEW.mailbox;
UPDATE mailboxes SET unread_count_adjusted_for_duplicates = MIN(unread_count_adjusted_for_duplicates + 1, unread_count) WHERE ((mailboxes.ROWID = NEW.mailbox AND mailboxes.source ISNULL) OR (mailboxes.ROWID IN (SELECT mailbox_id FROM labels WHERE message_id = NEW.ROWID) AND mailboxes.source = NEW.mailbox)) AND NEW.message_id = 0;
END;
CREATE TRIGGER after_update_duplicates_unread_count_becoming_unread AFTER UPDATE OF unread_count ON duplicates_unread_count WHEN OLD.unread_count = 0 AND NEW.unread_count = 1
BEGIN
UPDATE mailboxes SET unread_count_adjusted_for_duplicates = MIN(unread_count_adjusted_for_duplicates + 1, unread_count) WHERE (mailboxes.ROWID = NEW.mailbox_id AND mailboxes.source ISNULL) OR (mailboxes.ROWID IN (SELECT mailbox_id FROM labels WHERE message_id IN (SELECT ROWID FROM messages WHERE message_id = NEW.message_id AND mailbox = NEW.mailbox_id)) AND mailboxes.source = NEW.mailbox_id);
END;
CREATE TRIGGER after_update_duplicates_unread_count_becoming_read AFTER UPDATE OF unread_count ON duplicates_unread_count WHEN OLD.unread_count = 1 AND NEW.unread_count = 0
BEGIN
UPDATE mailboxes SET unread_count_adjusted_for_duplicates = MAX(MIN(1, unread_count), unread_count_adjusted_for_duplicates - 1) WHERE (mailboxes.ROWID = NEW.mailbox_id AND mailboxes.source ISNULL) OR (mailboxes.ROWID IN (SELECT mailbox_id FROM labels WHERE message_id IN (SELECT ROWID FROM messages WHERE message_id = NEW.message_id AND mailbox = NEW.mailbox_id)) AND mailboxes.source = NEW.mailbox_id);

DELETE FROM duplicates_unread_count WHERE rowid = NEW.rowid;
END;
CREATE TRIGGER after_insert_label AFTER INSERT ON labels
BEGIN
UPDATE mailboxes SET total_count = total_count + 1 WHERE mailboxes.ROWID = NEW.mailbox_id AND mailboxes.source IN (SELECT mailbox FROM messages WHERE ROWID = NEW.message_id LIMIT 1);
UPDATE mailboxes SET unseen_count = unseen_count + 1 WHERE mailboxes.ROWID = NEW.mailbox_id AND mailboxes.source IN (SELECT mailbox FROM messages WHERE ROWID = NEW.message_id AND flags&1 = 0 LIMIT 1);
UPDATE mailboxes SET deleted_count = deleted_count + 1 WHERE mailboxes.ROWID = NEW.mailbox_id AND mailboxes.source IN (SELECT mailbox FROM messages WHERE ROWID = NEW.message_id AND flags&2 != 0 LIMIT 1);
UPDATE mailboxes SET unread_count = unread_count + 1 WHERE mailboxes.ROWID = NEW.mailbox_id AND mailboxes.source IN (SELECT mailbox FROM messages WHERE ROWID = NEW.message_id AND flags&1 = 0 AND flags&2 = 0 LIMIT 1);
UPDATE mailboxes SET unread_count_adjusted_for_duplicates = MIN(unread_count_adjusted_for_duplicates + 1, unread_count) WHERE mailboxes.ROWID = NEW.mailbox_id AND mailboxes.source IN (SELECT mailbox FROM messages WHERE ROWID = NEW.message_id AND flags&1 = 0 AND flags&2 = 0 LIMIT 1) AND (SELECT count() FROM labels WHERE message_id IN (SELECT ROWID FROM messages WHERE message_id IN (SELECT NULLIF(message_id, 0) FROM messages WHERE ROWID = NEW.message_id) AND ROWID != NEW.message_id) AND mailbox_id = NEW.mailbox_id) = 0;
END;
CREATE TRIGGER after_delete_label AFTER DELETE ON labels
BEGIN
UPDATE mailboxes SET total_count = MAX(0, total_count - 1) WHERE mailboxes.ROWID = OLD.mailbox_id AND mailboxes.source IN (SELECT mailbox FROM messages WHERE ROWID = OLD.message_id LIMIT 1);
UPDATE mailboxes SET unseen_count = MAX(0, unseen_count - 1) WHERE mailboxes.ROWID = OLD.mailbox_id AND mailboxes.source IN (SELECT mailbox FROM messages WHERE ROWID = OLD.message_id AND flags&1 = 0 LIMIT 1);
UPDATE mailboxes SET deleted_count = MAX(0, deleted_count - 1) WHERE mailboxes.ROWID = OLD.mailbox_id AND mailboxes.source IN (SELECT mailbox FROM messages WHERE ROWID = OLD.message_id AND flags&2 != 0 LIMIT 1);
UPDATE mailboxes SET unread_count_adjusted_for_duplicates = MAX(MIN(1, unread_count), unread_count_adjusted_for_duplicates - 1) WHERE mailboxes.ROWID = OLD.mailbox_id AND mailboxes.source IN (SELECT mailbox FROM messages WHERE ROWID = OLD.message_id AND flags&1 = 0 AND flags&2 = 0 LIMIT 1) AND (SELECT count() FROM labels WHERE message_id IN (SELECT ROWID FROM messages WHERE message_id IN (SELECT NULLIF(message_id, 0) FROM messages WHERE ROWID = OLD.message_id) AND ROWID != OLD.message_id) AND mailbox_id = OLD.mailbox_id) = 0;
UPDATE mailboxes SET unread_count = MAX(0, unread_count - 1), unread_count_adjusted_for_duplicates = MIN(unread_count_adjusted_for_duplicates, unread_count - 1) WHERE mailboxes.ROWID = OLD.mailbox_id AND mailboxes.source IN (SELECT mailbox FROM messages WHERE ROWID = OLD.message_id AND flags&1 = 0 AND flags&2 = 0 LIMIT 1);
END;
CREATE TABLE properties (ROWID INTEGER PRIMARY KEY, key, value, UNIQUE (key));
CREATE TABLE conversations (conversation_id INTEGER PRIMARY KEY AUTOINCREMENT, flags INTEGER NOT NULL DEFAULT 0, sync_key TEXT);
CREATE TABLE conversation_id_message_id (conversation_id INTEGER NOT NULL REFERENCES conversations(conversation_id) ON DELETE CASCADE ON UPDATE CASCADE, message_id INTEGER NOT NULL DEFAULT 0, date_sent INTEGER DEFAULT 0,
PRIMARY KEY(conversation_id, message_id), FOREIGN KEY (conversation_id) REFERENCES conversations(conversation_id) ON DELETE CASCADE ON UPDATE CASCADE) WITHOUT ROWID;
CREATE INDEX conversation_id_message_id_conversation_id_message_id_index ON conversation_id_message_id(conversation_id, message_id);
CREATE INDEX conversation_id_message_id_message_id_conversation_id_index ON conversation_id_message_id(message_id, conversation_id);
CREATE TABLE message_metadata (message_id INTEGER PRIMARY KEY,
timestamp INTEGER NOT NULL,
json_values TEXT COLLATE BINARY NOT NULL);
CREATE INDEX message_metadata_timestamp_index ON message_metadata(timestamp);
CREATE TABLE recipients (ROWID INTEGER PRIMARY KEY,
message_id INTEGER NOT NULL REFERENCES messages(ROWID) ON DELETE CASCADE,
type INTEGER,
address_id INTEGER NOT NULL,
position INTEGER);
CREATE INDEX recipients_message_id_position_index ON recipients(message_id, position);
CREATE INDEX recipients_address_id_index ON recipients(address_id);
CREATE TABLE searchable_attachments (attachment_id INTEGER PRIMARY KEY,
attachment INTEGER REFERENCES attachments(ROWID) ON DELETE SET NULL,
message_id INTEGER,
transaction_id INTEGER NOT NULL);
CREATE INDEX searchable_attachments_attachment_index ON searchable_attachments(attachment);
CREATE INDEX searchable_attachments_message_id_index ON searchable_attachments(message_id);
CREATE TABLE local_message_actions (ROWID INTEGER PRIMARY KEY AUTOINCREMENT,
mailbox INTEGER REFERENCES mailboxes(ROWID) ON DELETE CASCADE,
source_mailbox INTEGER REFERENCES mailboxes(ROWID) ON DELETE CASCADE,
destination_mailbox INTEGER REFERENCES mailboxes(ROWID) ON DELETE CASCADE,
action_type INTEGER,
user_initiated INTEGER);
CREATE INDEX local_message_actions_mailbox_rowid_index ON local_message_actions(mailbox, ROWID);
CREATE TABLE action_flags (ROWID INTEGER PRIMARY KEY,
action INTEGER REFERENCES local_message_actions(ROWID) ON DELETE CASCADE,
flag_type INTEGER,
flag_value INTEGER);
CREATE INDEX action_flags_action_index ON action_flags(action);
CREATE TABLE server_labels (server_message INTEGER REFERENCES server_messages(ROWID) ON DELETE CASCADE,
label INTEGER REFERENCES mailboxes(ROWID) ON DELETE CASCADE,
PRIMARY KEY(server_message, label)) WITHOUT ROWID;
CREATE TABLE searchable_message_tombstones (ROWID INTEGER PRIMARY KEY AUTOINCREMENT,
type INTEGER NOT NULL,
identifier TEXT COLLATE BINARY NOT NULL,
transaction_id INTEGER,
UNIQUE(type, identifier) ON CONFLICT ABORT);
CREATE INDEX searchable_message_tombstones_transaction_id_type_identifier_index ON searchable_message_tombstones(transaction_id, type, identifier);
CREATE TABLE action_messages (ROWID INTEGER PRIMARY KEY,
action INTEGER REFERENCES local_message_actions(ROWID) ON DELETE CASCADE,
action_phase INTEGER,
message INTEGER REFERENCES messages(ROWID) ON DELETE SET NULL,
remote_id INTEGER,
destination_message INTEGER REFERENCES messages(ROWID) ON DELETE CASCADE);
CREATE INDEX action_messages_action_index ON action_messages(action);
CREATE INDEX action_messages_message_index ON action_messages(message);
CREATE INDEX action_messages_destination_message_index ON action_messages(destination_message);
CREATE TABLE searchable_messages (message_id INTEGER PRIMARY KEY,
message INTEGER REFERENCES messages(ROWID) ON DELETE SET NULL,
transaction_id INTEGER NOT NULL,
message_body_indexed INTEGER NOT NULL,
reindex_type INTEGER NOT NULL);
CREATE INDEX searchable_messages_message_reindex_type_transaction_id_index ON searchable_messages(message, reindex_type, transaction_id);
CREATE INDEX searchable_messages_reindex_type_message_id_index ON searchable_messages(reindex_type, message_id) WHERE reindex_type != 0;
CREATE INDEX searchable_messages_transaction_id_message_id_index ON searchable_messages(transaction_id, message_id);
CREATE TABLE attachments (ROWID INTEGER PRIMARY KEY AUTOINCREMENT,
message INTEGER NOT NULL REFERENCES messages(ROWID) ON DELETE CASCADE,
attachment_id TEXT COLLATE BINARY,
name TEXT COLLATE BINARY,
UNIQUE(message, attachment_id) ON CONFLICT ABORT);
CREATE INDEX attachments_message_name_index ON attachments(message, name);
CREATE INDEX attachments_message_attachment_id_index ON attachments(message, attachment_id);
CREATE TABLE server_messages (ROWID INTEGER PRIMARY KEY AUTOINCREMENT,
message INTEGER REFERENCES messages(ROWID) ON DELETE SET NULL,
mailbox INTEGER NOT NULL REFERENCES mailboxes(ROWID) ON DELETE CASCADE,
sequence_identifier INTEGER,
read INTEGER NOT NULL,
deleted INTEGER NOT NULL,
replied INTEGER NOT NULL,
flagged INTEGER NOT NULL,
draft INTEGER NOT NULL,
forwarded INTEGER NOT NULL,
redirected INTEGER NOT NULL,
junk_level_set_by_user INTEGER NOT NULL,
junk_level INTEGER NOT NULL,
flag_color INTEGER NOT NULL,
remote_id INTEGER NOT NULL,
UNIQUE(mailbox, remote_id) ON CONFLICT ABORT);
CREATE INDEX server_messages_message_index ON server_messages(message);
CREATE TABLE message_references (ROWID INTEGER PRIMARY KEY,
message INTEGER NOT NULL REFERENCES messages(ROWID) ON DELETE CASCADE,
reference INTEGER NOT NULL DEFAULT 0,
is_originator INTEGER NOT NULL DEFAULT 0);
CREATE INDEX message_references_message_reference_index ON message_references(message, reference);
CREATE INDEX message_references_reference_message_index ON message_references(reference, message);
CREATE TABLE action_labels (ROWID INTEGER PRIMARY KEY,
action INTEGER REFERENCES local_message_actions(ROWID) ON DELETE CASCADE,
do_add INTEGER,
label INTEGER REFERENCES mailboxes(ROWID) ON DELETE CASCADE);
CREATE INDEX action_labels_action_index ON action_labels(action);
CREATE INDEX action_labels_label_index ON action_labels(label);
CREATE TABLE message_global_data (ROWID INTEGER PRIMARY KEY AUTOINCREMENT,
message_id INTEGER,
UNIQUE(message_id) ON CONFLICT ABORT);
CREATE TABLE protected_message_data (ROWID INTEGER PRIMARY KEY,
data TEXT COLLATE BINARY);
CREATE TABLE summaries (ROWID INTEGER PRIMARY KEY AUTOINCREMENT,
summary TEXT COLLATE RTRIM NOT NULL,
UNIQUE(summary) ON CONFLICT ABORT);
