> This fork targets the Fujitsu LIFEBOOK ETU906Axx-E (`1c7a:05b1`) on Linux
> x86_64. See [ETU906.md](ETU906.md) for packaging, verification status and
> limitations. Hardware acceptance is not complete; CI success does not certify
> login or unlock support.

> [!WARNING]
> **Expired-certificate exception (v0.1.2+): disabled by default.**
> Setting `LIBFPRINT_SDCP_EXPIRED_MODEL_SHA256` explicitly accepts the expiry of
> the model certificate with that exact SHA-256 fingerprint. This weakens the
> normal certificate validity policy and is a temporary compatibility option,
> not a certificate renewal or proof that the device is safe. Model certificates
> can be shared by multiple sensors; this does not identify a unique physical device.
> Certificate-chain trust, certificate signatures, SDCP attestation signatures
> and MAC checks remain enabled. Expired issuers and other validation errors
> are still rejected. Hardware login/unlock acceptance is not complete.

### Enable the expired-model exception for the investigated LIFEBOOK sensor

Install v0.1.2 or later first. The fingerprint below was read from this sensor;
only use it if your diagnostic output has the same SHA-256 value. Configure
fprintd's service environment (setting a variable in the client shell is not enough):

```sh
sudo install -d -m 0755 /etc/systemd/system/fprintd.service.d
sudo tee /etc/systemd/system/fprintd.service.d/etu906-expired-model.conf >/dev/null <<'EOF'
[Service]
Environment=LIBFPRINT_SDCP_EXPIRED_MODEL_SHA256=288c1e9ac8282125597fde1f077d613739ebd4f5d69d0dd8a31bffa338f12833
EOF
sudo systemctl daemon-reload
sudo systemctl restart fprintd.service
fprintd-enroll -f right-index-finger "$USER"
fprintd-verify -f right-index-finger "$USER"
```

Restarting fprintd interrupts any active fingerprint operation. Keep password
login available. To restore strict expiry checking, remove only this override:

```sh
sudo rm /etc/systemd/system/fprintd.service.d/etu906-expired-model.conf
sudo systemctl daemon-reload
sudo systemctl restart fprintd.service
```

The package does not create or remove this administrator-owned override.
Remove it when no longer needed, including when uninstalling the private driver.

<div align="center">

# LibFPrint

*LibFPrint is part of the **[FPrint][Website]** project.*

<br/>

[![Button Website]][Website]
[![Button Documentation]][Documentation]

[![Button Supported]][Supported]
[![Button Unsupported]][Unsupported]

[![Button Contribute]][Contribute]
[![Button Contributors]][Contributors]

</div>

## History

**LibFPrint** was originally developed as part of an
academic project at the **[University Of Manchester]**.

It aimed to hide the differences between consumer
fingerprint scanners and provide a single uniform
API to application developers.

## Goal

The ultimate goal of the **FPrint** project is to make
fingerprint scanners widely and easily usable under
common Linux environments.

## License

`Section 6` of the license states that for compiled works that use
this library, such works must include **LibFPrint** copyright notices
alongside the copyright notices for the other parts of the work.

**LibFPrint** includes code from **NIST's** **[NBIS]** software distribution.

We include **Bozorth3** from the **[US Export Controlled]**
distribution, which we have determined to be fine
being shipped in an open source project.

## Get in *touch*

 - [IRC] - `#fprint` @ `irc.oftc.net`
 - [Matrix] - `#fprint:matrix.org` bridged to the IRC channel
 - [MailingList] - low traffic, not much used these days

<br/>

<div align="right">

[![Badge License]][License]

</div>


<!----------------------------------------------------------------------------->

[Documentation]: https://fprint.freedesktop.org/libfprint-dev/
[Contributors]: https://gitlab.freedesktop.org/libfprint/libfprint/-/graphs/master
[Unsupported]: https://gitlab.freedesktop.org/libfprint/wiki/-/wikis/Unsupported-Devices
[Supported]: https://fprint.freedesktop.org/supported-devices.html
[Website]: https://fprint.freedesktop.org/
[MailingList]: https://lists.freedesktop.org/mailman/listinfo/fprint
[IRC]: ircs://irc.oftc.net:6697/#fprint
[Matrix]: https://matrix.to/#/#fprint:matrix.org

[Contribute]: ./HACKING.md
[License]: ./COPYING

[University Of Manchester]: https://www.manchester.ac.uk/
[US Export Controlled]: https://fprint.freedesktop.org/us-export-control.html
[NBIS]: http://fingerprint.nist.gov/NBIS/index.html


<!---------------------------------[ Badges ]---------------------------------->

[Badge License]: https://img.shields.io/badge/License-LGPL2.1-015d93.svg?style=for-the-badge&labelColor=blue


<!---------------------------------[ Buttons ]--------------------------------->

[Button Documentation]: https://img.shields.io/badge/Documentation-04ACE6?style=for-the-badge&logoColor=white&logo=BookStack
[Button Contributors]: https://img.shields.io/badge/Contributors-FF4F8B?style=for-the-badge&logoColor=white&logo=ActiGraph
[Button Unsupported]: https://img.shields.io/badge/Unsupported_Devices-EF2D5E?style=for-the-badge&logoColor=white&logo=AdBlock
[Button Contribute]: https://img.shields.io/badge/Contribute-66459B?style=for-the-badge&logoColor=white&logo=Git
[Button Supported]: https://img.shields.io/badge/Supported_Devices-428813?style=for-the-badge&logoColor=white&logo=AdGuard
[Button Website]: https://img.shields.io/badge/Homepage-3B80AE?style=for-the-badge&logoColor=white&logo=freedesktopDotOrg
