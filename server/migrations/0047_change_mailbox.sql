-- The mailbox a change happened in.
--
-- A destroyed message has no row left to look its mailbox up from, and a shared folder must
-- not reveal which of its owner's other messages were deleted. Rows written before this column
-- existed keep NULL and are treated as private.
ALTER TABLE changes ADD COLUMN mailbox_id INTEGER;
