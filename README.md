# Apereo .NET CAS Client #

[![Build status](https://ci.appveyor.com/api/projects/status/py9b6esq9smjr6u5/branch/master?svg=true)](https://ci.appveyor.com/project/mmoayyed/dotnet-cas-client/branch/master)
[![Stable nuget](https://img.shields.io/nuget/v/DotNetCasClient.svg?label=stable%20nuget)](https://www.nuget.org/packages/DotNetCasClient/)
[![Pre-release nuget](https://img.shields.io/myget/dotnetcasclient-prerelease/v/dotnetcasclient.svg?label=pre-release%20nuget)](https://www.myget.org/feed/dotnetcasclient-prerelease/package/nuget/DotNetCasClient)
[![Unstable nuget](https://img.shields.io/myget/dotnetcasclient-ci/v/dotnetcasclient.svg?label=unstable%20nuget)](https://www.myget.org/feed/dotnetcasclient-ci/package/nuget/DotNetCasClient)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

[![Gitter](https://img.shields.io/gitter/room/apereo/cas.svg)](https://gitter.im/apereo/dotnet-cas-client)
[![Stack Overflow](https://img.shields.io/badge/stackoverflow-cas%20%2B%20.net-orange.svg)](https://stackoverflow.com/questions/tagged/cas%2b.net)

## Introduction ##

This is a fork of the Apereo .NET CAS client provides CAS integration for the Microsoft Windows platform via the .NET framework.

## Features ##

- Supports CAS Protocol 1.0 and 2.0 and SAML 1.1
- Supports CAS single sign-out
- Rich support for Microsoft ASP.NET platform integration through Forms Authentication framework


## Dotnet Core ##

The dotnet core implementation is currently under development. In the current build it has been tested for one use case. Setting up the dotnet core application to use CAS is much easier.

First go into the `Startup.cs` file. and in the `ConfigureServices` function add the folloing code:

```C#
  services.AddCass(new CasOptions
  {
    CasServerUrlPrefix = "REQUIRED",
    CasServerLoginUrl = "REQUIRED",
    ServerName = "REQUIRED",
    TicketValidatorName = TicketValidatorNames.Name,
    etc.
  });
  ```

  This will setup the optiosn for Cas Authentication which will use Cookie Authentication.

  Then in the same file add `app.UseCas()` to the `Configure` Method before it calls `app.UseMvc()`.

  This will map the "/Cas/" paths to use the CasMiddleware which will handle logging in and logging out.