/*
  Warnings:

  - You are about to drop the column `url` on the `threat_reports` table. All the data in the column will be lost.

*/
-- AlterTable
ALTER TABLE "public"."threat_reports" DROP COLUMN "url";
