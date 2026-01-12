CREATE TABLE IF NOT EXISTS inodes (
                                      ino         BIGSERIAL PRIMARY KEY,
                                      mode        INTEGER NOT NULL,
                                      size        BIGINT NOT NULL DEFAULT 0,
                                      nlink       INTEGER NOT NULL DEFAULT 1,
                                      created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                                      updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),

                                      CONSTRAINT positive_nlink CHECK (nlink >= 0)
);

CREATE TABLE IF NOT EXISTS dir_entries (
                                           parent_ino  BIGINT NOT NULL REFERENCES inodes(ino) ON DELETE CASCADE,
                                           name        VARCHAR(255) NOT NULL,
                                           child_ino   BIGINT NOT NULL REFERENCES inodes(ino) ON DELETE RESTRICT,

                                           PRIMARY KEY (parent_ino, name),
                                           CONSTRAINT no_dot_entries CHECK (name NOT IN ('.', '..'))
);

CREATE TABLE IF NOT EXISTS file_content (
                                            ino         BIGINT PRIMARY KEY REFERENCES inodes(ino) ON DELETE CASCADE,
                                            data        BYTEA NOT NULL DEFAULT ''::bytea
);

CREATE INDEX IF NOT EXISTS idx_dir_entries_child ON dir_entries(child_ino);

-- Root directory: mode 16895 = 040777 (directory + rwxrwxrwx)
DO $$
    BEGIN
        IF NOT EXISTS (SELECT 1 FROM inodes WHERE ino = 1) THEN
            INSERT INTO inodes (ino, mode, size, nlink) VALUES (1, 16895, 0, 2);
            PERFORM setval('inodes_ino_seq', 1);
        END IF;
    END $$;