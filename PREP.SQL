
CREATE DATABASE [sophos_test]

USE [sophos_test]


CREATE TABLE [dbo].[siem_state_account](
	[accountid] [nvarchar](250) NOT NULL,
	[jwt] [ntext] NULL,
	[jwtExpiresAt] [float] NULL,
	[whoami_id] [nvarchar](250) NOT NULL,
	[whoami_idtype] [nvarchar](50) NULL,
	[whoami_apiHost_global] [nvarchar](250) NULL,
	[whoami_apiHost_dataRegion] [nvarchar](250) NULL,
	[access_token] [ntext] NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO


CREATE TABLE [dbo].[Event](
	[EVENTID] [int] IDENTITY(1,1) NOT NULL,
	[source_info] [varchar](50) NULL,
	[customer_id] [varchar](50) NOT NULL,
	[type] [varchar](50) NULL,
	[id] [varchar](50) NOT NULL,
	[group] [varchar](50) NULL,
	[name] [varchar](250) NULL,
	[datastream] [varchar](50) NOT NULL,
	[rt] [varchar](50) NULL,
	[end] [datetime] NULL,
	[dhost] [varchar](50) NULL,
	[severity] [varchar](50) NOT NULL
) ON [PRIMARY]
GO
