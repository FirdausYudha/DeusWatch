-- Intentionally empty.
--
-- The up migration repairs accounts that could see nothing. It cannot be reversed, because a
-- Default membership added here is indistinguishable from one added by 000049 or by CreateUser,
-- and removing them all would re-break every ordinary user on the deployment.
SELECT 1;
