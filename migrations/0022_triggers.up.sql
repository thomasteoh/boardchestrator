-- 0022: agent triggers on board columns (WU-307)
-- task.move into a column with a trigger_agent_id enqueues an agent run with
-- the interpolated trigger_prompt as the instruction.

ALTER TABLE board_columns ADD COLUMN trigger_agent_id TEXT REFERENCES agents(id);
ALTER TABLE board_columns ADD COLUMN trigger_prompt TEXT NOT NULL DEFAULT '';
