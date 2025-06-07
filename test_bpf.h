/* SPDX-License-Identifier: GPL-2.0
 *
 *  Test wrappers for bpf functions
 *  Copyright (C) 2025  Perry Lorier
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#ifndef TEST_BPF_H
#define TEST_BPF_H

#ifndef BPF
#undef __arg_ctx
#undef __arg_nullable
#undef __arg_nonnull
#define __arg_ctx
#define __arg_nullable
#define __arg_nonnull

#undef SEC
#define SEC(section)
#endif


#endif
