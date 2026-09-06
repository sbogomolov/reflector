#!/usr/local/bin/php
<?php

/*
 * Copyright (C) 2026 Sergii Bogomolov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Two checks against this core's field types, exit 1 on any finding. Nothing
 * is written: the model instances live in memory only.
 *
 * Structural: every tag in the model XML must map to a set<Tag>() method on
 * its field type. BaseModel drops unknown tags without a word (hasMethod()
 * filter), so a typo or a guessed name silently disables the option it was
 * meant to set.
 *
 * Behavioural: the multi-value fields must accept lists and still reject bad
 * items. The structural check cannot see an OMITTED tag (a CSVListField
 * without MaskPerItem validates "7,9" against the whole-string mask), so the
 * list handling is exercised for real.
 */

use OPNsense\Netflector\Netflector;

require_once 'script/load_phalcon.php';

$failures = 0;

function fail(string $message): void
{
    global $failures;
    $failures++;
    echo 'FAIL: ' . $message . PHP_EOL;
}

/* structural: no silently ignored model tags */
$model_xml = '/usr/local/opnsense/mvc/app/models/OPNsense/Netflector/Netflector.xml';
$walk = function ($node) use (&$walk) {
    foreach ($node->children() as $field) {
        $type = (string)($field->attributes()['type'] ?? '');
        if ($type === '') {
            $walk($field);
            continue;
        }
        if (str_starts_with($type, '.\\')) {
            $cls = 'OPNsense\\Netflector\\FieldTypes\\' . substr($type, 2);
        } else {
            $cls = str_contains($type, '\\') ? $type : 'OPNsense\\Base\\FieldTypes\\' . $type;
        }
        if (!class_exists($cls)) {
            fail(sprintf('%s: field type %s does not exist in this core', $field->getName(), $type));
            continue;
        }
        $rf = new ReflectionClass($cls);
        foreach ($field->children() as $tag) {
            $name = $tag->getName();
            if (($tag->attributes()['type'] ?? null) !== null || $name === 'OptionValues') {
                continue;
            }
            if (!$rf->hasMethod('set' . $name)) {
                fail(sprintf('%s (%s): <%s> has no set%s(), BaseModel ignores it', $field->getName(), $type, $name, $name));
            }
        }
        $walk($field);
    }
};
$walk(simplexml_load_file($model_xml)->items);

/* behavioural: list fields take lists, bad items still fail */
function validation_messages(string $macs, string $wol_ports): array
{
    $model = new Netflector();
    $entry = $model->reflectors->reflector->Add();
    $entry->enabled = '1';
    $entry->name = 'modelcheck';
    $entry->wol = '1';
    $entry->macs = $macs;
    $entry->wol_ports = $wol_ports;
    $messages = [];
    foreach ($model->performValidation() as $message) {
        $field = $message->getField();
        /* only the fields under test: the synthetic entry has no interfaces */
        if (str_ends_with($field, '.macs') || str_ends_with($field, '.wol_ports')) {
            $messages[] = $field . ': ' . $message->getMessage();
        }
    }
    return $messages;
}

foreach (
    [
        ['aa:bb:cc:dd:ee:ff,11:22:33:44:55:66', '7,9', true],
        ['aa:bb:cc:dd:ee:ff', '7', true],
        ['aa:bb:cc:dd:ee:ff,nonsense', '7', false],
        ['aa:bb:cc:dd:ee:ff', '7,70000', false],
        ['aa:bb:cc:dd:ee:ff', '07', false],
        /* core's field takes hyphen and dot forms in either case; the template folds them, and a
           repeat in two spellings is the daemon's to refuse */
        ['aa-bb-cc-dd-ee-ff', '7', true],
        ['aabb.ccdd.eeff', '7', true],
        ['aa:bb:cc:dd:ee:ff,AA:BB:CC:DD:EE:FF', '7', true],
        ['aa:bb:cc:dd:ee:ff,aabb.ccdd.eeff', '7', true],
        ['aa:bb:cc:dd:ee:ff', '7,7', true],
    ] as [$macs, $wol_ports, $expect_valid]
) {
    $messages = validation_messages($macs, $wol_ports);
    if ($expect_valid && $messages !== []) {
        fail(sprintf('macs=%s wol_ports=%s rejected: %s', $macs, $wol_ports, implode(' | ', $messages)));
    } elseif (!$expect_valid && $messages === []) {
        fail(sprintf('macs=%s wol_ports=%s accepted, expected a validation error', $macs, $wol_ports));
    }
}

if ($failures === 0) {
    echo 'model check ok' . PHP_EOL;
    exit(0);
}
exit(1);
