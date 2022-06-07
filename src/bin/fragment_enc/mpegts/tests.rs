// fragment-enc - MPEG-TS/AAC muxing support (Tests)
//
// Copyright (C) 2022 Tim-Philipp Müller <tim centricular com>
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// <https://mozilla.org/MPL/2.0/>.
//
// SPDX-License-Identifier: MPL-2.0

#[cfg(test)]
#[test]
fn write_pes_183bytes_in_last_packet() {
    gst::init().unwrap();

    // already written packets (content doesn't matter)
    let mut chunk = vec![0xffu8; 59032];
    let aac_config = super::AacConfig {
        mpeg_version: 4,
        channels: 2,
        rate: 48000,
        aot: 2,
    };
    let frame0 = base64::decode("IRqU1f1ve6r25+GZ96r4mL31pDUXdSXa7Vg0faQf36l+Xwj7b2lyaYpVqC3QuWgAdq/i2vbv4LC5aLTyh6r5tnvNGo2BblcTpo9s2eGWA7D3Mx2kDp53bek0caxbVdk/6/XPtem0HJcjfppVHjrRd+6FYrdDMwY67DO/k5RDrPxb+Pn2VheARtTZIAe1N0d1S6T2GVwdiXJYfGu8uZfLcT5qinu91h7DFnce2fA9X8G1dhXF/NlFk6v5aj/nW+MtdMfTd7dzTqHt7qnVNZh7x1V2bMx6MU/pbDRQ9veu2Erev01Mev//+89jcr+j/o5AH1Bvz4zqv5Sr+1+SNiZS0TVlRBpb0LVXrMf7/hErh4xsOpyc4QWO6AB5xyjxZKZacrkNVxzR8sA+80zikVi3RNI45pbuuZR1fxn4BMpa5Boaef0dt0+Y91zqR9cKG5fg/7eiHCt5Q6rYIR+uy99Q6G/09UNfpNJ8ID7HylcOr72vLdOIcvHKyBv7aLp5JnNigh+L9fj3X/TKPyTBwbmzThvdvQ3dHzv49LfzdDdB/llizwUZ3fvbS3W9VzX7/5XTnPCzvKtgf47L0L6z+82/j4PQncXTmyj4aDpeZSVKDsz6Zuf/XnL7fWAdF0UXQtmg/CwXxHzuruLckfhPsNoBn0OquZdkVcxcyeo6az131VvueU3rSfim2uve8B3tlzKXkzhfWi7wjhwzlxw5LuHJDyAAATtSZqFgznStb6tz+tOJkZrVaquIu6jVzgUHuIt1XudcHXKrVR3m2VOSN3UvoXxF9loB24ZzWJ5MgiYDCGyMaxUr3w1J8+xQbsZ4fDqJBZZTTt4wNref1FChJApgmZ3/CkTEGsAK7hGa7vKjqwesIkADBDNjEDrAzO3jR3BIgFBKmvMEJInomotS8jqaqJ6hvGNssI9zQwEhICiIOpUFHQXMmJjFF5X8GzjpcHt5meYY0U0QzQ1LM7b1wIRjOsR3TQWQD9ZBhQgjhEmitCFJOrxCk3NGnT2SSSJ2iXGlV20NikYNKC50l3l0K6SSuSkdVMiAprbTEzIQZVTl1mRX1fDt1jJyzJlKSe/WnfC9UT3ULettTuc5zuA=").unwrap();
    let frame1 = base64::decode("IRqU7f1ub288+fb3v4mea3qqu5JLaktd3WpdYI9n8FbArztX8HP4HN2ywRD635U3O2eGeL/kvUPOqhD9m2x0fkf1HdGt5kBYGkaEC0WT57kwPB6dqYP7T/nl7z/tyfx5d62/NvfRs+h7pwIH0vxjhQ988SW7bpHgXuuUOFFza79r7x0J5ddIOnvj8R8ic90k7QqqzQ9pZ/7Vh/GVui/Ob2sUPo2l+3XD3N8D8NLZMeh6S6z6txLa2r6p4H9pnYE1/EodYXSDpTna7Q/UotzCnxb1eTg4ECTR+aYV3T29+P3T2h2J/l+kefes5GloH/2YdJZF5g3d27bwfgqhBS8rF7/9M8ovmyfJO//hPs36GxOYuS8gE/6eJ7Q+W+2+IeJPzUGxKWlkNpA5v0jx84qBDKQO7bRBobf+vddYdrr65JX/jlDdtiA4JyTxTrKGOOPNj/TZMJHn+fmp/7p4n8X4nqPU1DBpbvP1GC0OLwO4cZ1bzB9SrUEdcCz4tTjdv1C0AXiqWzejmkV1f0LZy7mWwa/gnR/hf5uPuRXPtaD8IDD560TsTlXE7EB9v495qzH5plzZmce1PvmvPxv1/sfL2Npub+suPdWUZKZMoa3cGpY8yzeja8V//tq3J6wL/Q3p9r2D9I8H0DtnyGNPyGrpA3ZsDkqwJ1D8rcG391c+4ruMmEPcvEmG4NVSNtFjaB/B4HHkYRhiG5IQ5Ik00fZDqj4XVKw2r8AAAT9MZqKYkDZatVrrufW883VTNcEziLupOLzhpgWhjIN0+l1CEPQZ7/bdAgXpnu9gzR5HD2Sv49aiR3sSjPtSrpJ44fH049vT201sufVJtlWUHq0KISSnV4nLnt7v6sqzOpbK+l8l64SmLB3dJlPaYtJUvCapK7rXxv4oFypLzjmeu/T5Ld9Hk2uxwzKv14Tj8s/f+cCNQTcdx1bCb16UeHAlDa2G6hPWh59NH3XVuqmbr52U2+j6tLk9369mnuQmrmfasPdhEXg5WDW2QTnBWRjnyWeXlMLZT7Z0zsvektQDLkIulXCm9VkPpVc/Ys0RTy7EkbceXi/qOri95VWNkfjv0HwLAWK+5znO4A==").unwrap();
    let frame2 = base64::decode("ISqU3f1vHXL48X1vXlXW7luFlokk1aXJKExWmCiQUp9m3po2pwUCG8OEBbFbgRdWc9eeaDUQHDQI+d4FTPBaBHMGI/EuywLFF3hhOlLpH8zvTBwT+CY/xq3D97t0WE7FzDSuDAzD+37Z7Azd4HpjxCNaCF8PGEdN21ieRdJ+DbfxzOgrpB+k5ElwH3KVgYpz900SAH1rsjkSZgbK7e5u0n/q/37i9m27KhM92X/m+nSiLnbtukpH0LlinoFJg6RivTOQQctd1et9u3nrK1xUWLdM/A+C/hdlx//Lzcw+Ya1jd88S/5U19p+J9V4fgwtnWVpOfh9+VOh0ZDF+exz5V4xhXI/c823teUnEjNFlqgjetf7wSj/C9a80bG3RoTdPBv6MphoEH32j+bKR5P25KI6Vds9457D5D2/cV7/KNVZG7gt03tO4bYb+o5sFt0soBGm723KpoB2j871jt69sW5tiFVbCzJ6/8ZmPduK1RqzfnOz92R/d9K9g+q/ftg99ffp78X+V46DMNWVqDMOBBtnvPtTLLjn4U/E/JaIukTXmLoaqfvNmgjiPfB6KAlw/4iJbCwMFCD/uw707NfKlxfZu/Nd8Am/SfgDouC3z9DeWSNfdGfYexYD9v7g0L2PEYz358tlYVTE2V2dpu2fdY01puPNuSLNL1rEvWpXHEahFB+y9WLU90f+BibFl5irzj6mczc9XhrL8zb1N5bzLXzgSReQoJliagAAE9aoQykMw4K3wrrt5m/jb25tc1VpEq5HGj4GCBCHTHLfez/YNUNEEEkQ+2VzjU/Pc3WARK/JboxzPufLlJRfe/34tc3SAxPKsLhDPZOmV8qRKY8PKGH0y8LMJ46NyU5IKXn54PU8cB31XV11+SS3fJ74DD228pRwKvAbnes1kwnJLq8yqLALoTz6BKRoR1Vrc6RJk9m2m8m6rlehMLQH4YCuEBtGUm2x+c1K4LgrEFhGpsMmL3oLMh/KUlTT0nbOAYJvwxraVxlzNraJwG1wFDYKiyOq0TWUDpfesav6l2dGnQQHKQl+7ob9arBXv+56dX8F1fra+qs+XQ3doyhYdT+/WK9nW2tfcZhd+KqbaeIvI6GmqLOW9HqaTLbcheifc5znc").unwrap();
    let frame3 = base64::decode("IUw3TF+37ft+vjzfxH3y2f/3ute01d9ce2f/2Na83d3x8Tz//S4cammvPFj0X7J+9o61wTZ+1VfedUwLs3YXafmWodQunwzSN1A789Y6R7LzLD/wfK6nuVbuZu1VIfZMxNlQftPJxHkADp36vQQc+fuJ41R9U+0dx+z/cOuNPkLpf/PxPjNQ0DK4ZmHgAMQ153TDseD1BG1LIdH9xTIKVwRTMGZtCN2DQNIABUYJMDlD7h9T+Zyh/2mQTF3o2PVpXHIF4/9bi6Lh0vD+kMUwSS/61F8Z8lxVY40nO/YdFAgFkZ69C5o+B5SyED//1BS/77oDi0XQmyPEL62H4dIfUuttLY4ywQITVua1aVDdAWFva2b1mzw05h7Zd2PC0gv+E9x87/9ZGpzVXhJH7g6qivQc1P+fLRAaPod4cUNh+N47NYZEpudMUXsGvSZ0cXQFzSBS+ubap6DAATy3st0YcAAIGPQA/ycDXAAVCOkup+l+43/YpI14Kqb0UPr1guyMsmCogFOTHEccEAD+66h9g1vkTueWx6g3Htbxrv7wzHUK/4WsH41TlsUw5ZxxxHx/HhI94JnvtT+xinSeraiDmPJgL70f8R05kEPynanxkxaDIlLSmyAalpVhON71nmSlYBpXkluWRMGW81/ZOrfW6fsjtKUS3eLF37yl8X5j5A3/HMki2kR37bzHsOeO1/w0/gxVv0tvV+6PeG0ABMfcqnZLbAAW9Y3FIDQABJXWaSy2ssxNpmloqbMJMSEq8z70++XK//DOOPiP58dVn/xVatd9e34r/+1dXKtx1xY9V2CoDpgRCv5mC010o49tRl+hS29lXaC+OgqwFb1CHEdwCFModXr6DdPdkW6074+54+J2Vt/epmCeaaaxLIVgzL6dtdy5k/6RsicC7l2E07Dq783CzOqEB6sTbTrlKVwuicdRDG2yz8S/UVawm1+kgRosbuOL5ahkWAgAJjgG00goaR3tkUgQnfDI7+zG6H+PGezmP+2J1wL5ji7xwjrbSrHwFsokAmabNCwSlp6UUcXxllbm2LoBHeSPQNADv16nhI2kKtsZ+wWyrJtBv7GeFz1iPA0iFLS0tLS0tLS8").unwrap();
    let frame4 = base64::decode("IXqU3f1pU3GueK+PHW+lU1KjLStW1qS7jYnV5B5iBMSTCSgmZ0QTkwScBNse5dEkFhqc/cHmf1uTyI53Pu3eLnwIfvN7vnrKWRS8fqrm7iV1CscM97w9OuoFRA1fJcY49F4BPgKmDYHgH5Lv7qji7nazhfJf+XYX6bTX37TXT1NVEGph7osqfg2sZJ8Xs2Yufq7B0XYoOaO7c6gbFPyD1r/tUwPtt1m7wwjLFjD8Sl0E9b6q6Vja/ycGoBYd+CxOw+6aJBkE/jhJAaS5u3NDfWcQ5p+irIcO8O+f6QmKfR1qP53oi3hy+PSPH9RgrE/wXJv4rgfsPRfhu8eJG87WV/LgRcVKoEWtaR0X+myaLp6+ZRBsHu3uDX9ySPnUX/EiIOWMfE7o786a2VE376RYwe10POe+4HXQZ9FxG6S3NQAkUY1CDjoufujsp9k4+NZo/hv8vh3r3s3PGh8MY+rPJJ1Bk0npP37+piR/yth+JjVUfuu3TvC6jVad+oaM1Ppl+bc6xjbzncz/4Ukmkzz394turb00657z0Zm2tR7OqIWj/mZFl0ktD+VoIXbz9viH90/IWcHf9mgkXKwpeDVWKca7m5uyqn9rsq8UfQOpbDg+sqtzsns77d4BKxO/Nlbm8G9j7lzFXvcWrjdFfYfmeXJH9ut0jkgf7bBwdofnp7/FbewjmK6Sc6a+5P7a3z/Sy09Zbji9BKt/e61ublvbi3zDpHlH67GMKd0TZvTtQOlFPUZSFElwAABP2SksZCkNDkJCiFUuqkrVfXz1viVjUqVlyVq2tSXcYIGgUB4OlvGhSc1rJDe4xx6bVANw0YzZ5lrOXYbwWiOAO7ecGicsxChvmECCaEakI0MjJ32yqtLQzBAV8EQ9BFUn9PYxtOPyQwHb53LJ3E8LUno0VrTPI4TdrDM4QVEQquiXPZWZVbeXwwMDHauVAaDKthe1/cgxVJDlAqtuIlMLj8mBeaGq9nLWVSPDVFbZSnZvPdwDjaa8n1UQrTtPG9YHu3KiPPEV7QN6GIUtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLw==").unwrap();

    use super::EncodedFrame;

    let frames = vec![
        EncodedFrame {
            pts: Some(gst::ClockTime::from_nseconds(33386666666)),
            buffer: gst::Buffer::from_slice(frame0),
        },
        EncodedFrame {
            pts: Some(gst::ClockTime::from_nseconds(33408000000)),
            buffer: gst::Buffer::from_slice(frame1),
        },
        EncodedFrame {
            pts: Some(gst::ClockTime::from_nseconds(33429333333)),
            buffer: gst::Buffer::from_slice(frame2),
        },
        EncodedFrame {
            pts: Some(gst::ClockTime::from_nseconds(33450666666)),
            buffer: gst::Buffer::from_slice(frame3),
        },
        EncodedFrame {
            pts: Some(gst::ClockTime::from_nseconds(33472000000)),
            buffer: gst::Buffer::from_slice(frame4),
        },
    ];
    let mut cc: u8 = 8;
    super::write_pes(
        &mut chunk,
        &aac_config,
        &frames,
        &mut cc,
        super::PesNoCounterPadding,
    );
}
