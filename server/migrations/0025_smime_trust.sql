-- Certificates collected under the former incomplete path validator have no
-- trustworthy provenance. Re-learn correspondents from newly verified mail.
DELETE FROM smime_certificates;
