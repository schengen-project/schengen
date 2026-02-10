// SPDX-License-Identifier: GPL-3.0-or-later

//! # Schengen
//!
//! A Rust library for the implementation of Synergy/Deskflow for mouse and keyboard sharing.
//!
//! This crate provides the API for building a Synergy/Deskflow client or server and the [protocol]
//! for parsing messages.
//!
//! ## Deskflow vs Synergy
//!
//! There are four different implementations that you should be aware of:
//! - [Synergy](https://symless.com/synergy): the original implementation, see also the [Wikipedia
//!   page](https://en.wikipedia.org/wiki/Synergy_(software))
//! - [Barrier](https://github.com/debauchee/barrier): a now-unmaintained fork of Synergy 1.9
//! - [Input-Leap](https://github.com/input-leap/input-leap): a now-(nearly?)-unmaintained fork of Barrier
//! - [Deskflow](https://github.com/deskflow/deskflow/): the currently maintained core component
//!   that is also used in Synergy (see [this blog
//!   post](https://symless.com/synergy/news/what-happened-to-the-old-barrier-fork) for some info)
//!
//! These four share the same code with some being direct descendents, DeskFlow had patches mostly
//! ported over from Input-Leap. The only real difference between Synergy and Barrier on the
//! protocol level seems to be in the Hello message of the handshake.
//!
//! Barrier, Input-Leap and Deskflow are protocol compatible and announce themselves via the
//! [protocol::MessageHelloBarrier]. For the purpose of this crate, Synergy and Deskflow are treated as
//! identical but since Synergy is the original, the term "Synergy" is used for the protocol.
//!
//! Long term this crate will more likely stay compatible with Deskflow though.
//!
//! # The name "schengen"
//!
//! The [Schengen Area](https://en.wikipedia.org/wiki/Schengen_Area) is the area in Europe where
//! there are no border controls. You can move from one country into another without being stopped
//! at the border. That seems appropriate enough for a project that lets you move between hosts.

pub mod client;
pub mod protocol;
pub mod server;
