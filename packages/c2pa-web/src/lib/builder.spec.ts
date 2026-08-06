/**
 * Copyright 2025 Adobe
 * All Rights Reserved.
 *
 * NOTICE: Adobe permits you to use, modify, and distribute this file in
 * accordance with the terms of the Adobe license agreement accompanying
 * it.
 */

import { test, describe, expect } from 'test/methods.js';
import { ManifestDefinition, Ingredient } from '@contentauth/c2pa-types';
import { getBlobForAsset } from 'test/utils.js';
import { Settings } from './settings.js';
import { createC2pa } from './c2pa.js';
import { Signer } from './signer.js';
import wasmSrc from '@contentauth/c2pa-web/resources/c2pa.wasm?url';

import C_JPG from 'test/assets/C.jpg';
import PirateShip_cloud from 'test/assets/PirateShip_save_credentials_to_cloud.jpg';
import signingPrivateKey from 'test/signing/es256.pem?raw';
import signingCertChain from 'test/signing/es256.pub?raw';

const C2PA_UUID = 'd8fec3d61b0e483c92975828877ec481';
const SENSITIVITY_LABEL_UUID = '4d495053fcf644baa37a29b1d8e4964f';
const SENSITIVITY_LABEL_XML = '<?xml version="1.0"?><Label />';

function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const result = new Uint8Array(
    arrays.reduce((length, array) => length + array.byteLength, 0)
  );
  let offset = 0;

  for (const array of arrays) {
    result.set(array, offset);
    offset += array.byteLength;
  }

  return result;
}

function makeBox(type: string, payload = new Uint8Array()): Uint8Array {
  const bytes = new Uint8Array(8 + payload.byteLength);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, bytes.byteLength);
  bytes.set(new TextEncoder().encode(type), 4);
  bytes.set(payload, 8);
  return bytes;
}

function hexToBytes(hex: string): Uint8Array {
  return Uint8Array.from(
    hex.match(/.{2}/g)?.map(byte => Number.parseInt(byte, 16)) ?? []
  );
}

function makeSensitivityLabelMp4(): Uint8Array {
  const ftypPayload = new Uint8Array(8);
  ftypPayload.set(new TextEncoder().encode('isom'));

  const sensitivityLabelPayload = concatBytes(
    hexToBytes(SENSITIVITY_LABEL_UUID),
    new TextEncoder().encode(SENSITIVITY_LABEL_XML)
  );

  return concatBytes(
    makeBox('ftyp', ftypPayload),
    makeBox('uuid', sensitivityLabelPayload),
    makeBox('free')
  );
}

interface TopLevelBox {
  type: string;
  uuid?: string;
  payload: Uint8Array;
}

function readTopLevelBoxes(bytes: Uint8Array): TopLevelBox[] {
  const boxes: TopLevelBox[] = [];
  const decoder = new TextDecoder();
  let offset = 0;

  while (offset < bytes.byteLength) {
    const view = new DataView(
      bytes.buffer,
      bytes.byteOffset + offset,
      bytes.byteLength - offset
    );
    const size = view.getUint32(0);
    const type = decoder.decode(bytes.subarray(offset + 4, offset + 8));

    if (size < 8 || offset + size > bytes.byteLength) {
      throw new Error(`Invalid ${type} box size: ${size}`);
    }

    const uuid =
      type === 'uuid'
        ? Array.from(bytes.subarray(offset + 8, offset + 24))
            .map(byte => byte.toString(16).padStart(2, '0'))
            .join('')
        : undefined;
    const payloadOffset = type === 'uuid' ? offset + 24 : offset + 8;

    boxes.push({
      type,
      uuid,
      payload: bytes.slice(payloadOffset, offset + size)
    });
    offset += size;
  }

  return boxes;
}

function decodePrivateKey(pem: string): Uint8Array {
  const base64 = pem
    .replace('-----BEGIN PRIVATE KEY-----', '')
    .replace('-----END PRIVATE KEY-----', '')
    .replace(/\s/g, '');
  return Uint8Array.from(atob(base64), character => character.charCodeAt(0));
}

async function createTestSigner(): Promise<Signer> {
  const privateKey = await crypto.subtle.importKey(
    'pkcs8',
    decodePrivateKey(signingPrivateKey),
    {
      name: 'ECDSA',
      namedCurve: 'P-256'
    },
    false,
    ['sign']
  );

  return {
    alg: 'es256',
    directCoseHandling: false,
    reserveSize: async () => 10_000,
    certs: async () => [signingCertChain],
    sign: async data =>
      new Uint8Array(
        await crypto.subtle.sign(
          {
            name: 'ECDSA',
            hash: 'SHA-256'
          },
          privateKey,
          data
        )
      )
  };
}

describe('builder', () => {
  describe('creation', () => {
    describe('new', () => {
      test('should create a builder with a default manifest', async ({
        c2pa
      }) => {
        const builder = await c2pa.builder.new();
        const definition = await builder.getDefinition();
        expect(definition).toEqual({
          assertions: [],
          claim_generator_info: [],
          format: '',
          ingredients: [],
          instance_id: ''
        });
      });

      test('should use local "context" settings when provided', async () => {
        const settings: Settings = {
          verify: {
            verifyTrust: false
          }
        };

        const overrideSettings: Settings = {
          verify: {
            verifyTrust: true
          }
        };

        const c2pa = await createC2pa({ wasmSrc, settings });

        const builder = await c2pa.builder.new(overrideSettings);

        const blob = await getBlobForAsset(C_JPG);

        await builder.addIngredientFromBlob({}, blob.type, blob);

        const definition = await builder.getDefinition();

        const ingredientFailureCodes =
          definition.ingredients?.[0].validation_results?.activeManifest?.failure.map(
            (entry) => entry.code
          );

        expect(ingredientFailureCodes).toContain('signingCredential.untrusted');
      });
    });

    describe('manifestDefinition', () => {
      test('should create a builder with the provided manifest definition', async ({
        c2pa
      }) => {
        const manifestDefinition: ManifestDefinition = {
          claim_generator_info: [
            {
              name: 'c2pa-web-test',
              version: '1.0.0'
            }
          ],
          title: 'Test_Manifest',
          format: 'image/jpeg',
          instance_id: '1234',
          assertions: [],
          ingredients: []
        };

        const builder = await c2pa.builder.fromDefinition(manifestDefinition);

        const manifestDefinitionFromBuilder = await builder.getDefinition();

        expect(manifestDefinitionFromBuilder).toEqual(manifestDefinition);
      });
    });

    describe('fromArchive', () => {
      test('should re-create a builder from an archive', async ({ c2pa }) => {
        const manifestDefinition: ManifestDefinition = {
          claim_generator_info: [
            {
              name: 'c2pa-web-test',
              version: '1.0.0'
            }
          ],
          assertions: [],
          format: '',
          ingredients: [],
          instance_id: ''
        };

        const builder = await c2pa.builder.fromDefinition(manifestDefinition);

        const archive = await builder.toArchive();

        const builderFromArchive = await c2pa.builder.fromArchive(
          new Blob([archive])
        );

        const definitionFromArchivedBuilder =
          await builderFromArchive.getDefinition();

        expect(definitionFromArchivedBuilder).toMatchObject(manifestDefinition);
      });

      test('should re-create a builder from an archive with ingredient from blob', async ({
        c2pa
      }) => {
        const manifestDefinition: ManifestDefinition = {
          claim_generator_info: [
            {
              name: 'c2pa-web-test',
              version: '1.0.0'
            }
          ],
          assertions: [],
          format: '',
          ingredients: [],
          instance_id: ''
        };

        const builder = await c2pa.builder.fromDefinition(manifestDefinition);

        const blob = await getBlobForAsset(C_JPG);
        const blobType = blob.type;

        const ingredient: Ingredient = {
          title: 'C.jpg',
          format: blobType,
          instance_id: 'ingredient-instance-123'
        };

        await builder.addIngredientFromBlob(ingredient, blobType, blob);

        const archive = await builder.toArchive();

        const builderFromArchive = await c2pa.builder.fromArchive(
          new Blob([archive])
        );

        const definitionFromArchivedBuilder =
          await builderFromArchive.getDefinition();

        expect(definitionFromArchivedBuilder.ingredients).toHaveLength(1);
        expect(definitionFromArchivedBuilder.ingredients![0]).toMatchObject({
          title: 'C.jpg',
          format: blobType,
          instance_id: 'ingredient-instance-123'
        });
      });

      test('should create a readable archive', async ({ c2pa }) => {
        const manifestDefinition: ManifestDefinition = {
          claim_generator_info: [
            {
              name: 'c2pa-web-test',
              version: '1.0.0'
            }
          ],
          title: 'Test_Manifest',
          format: 'image/jpeg',
          assertions: [],
          ingredients: [],
          instance_id: ''
        };

        // Create builder with generateC2paArchive enabled
        const builder = await c2pa.builder.fromDefinition(manifestDefinition);

        const blob = await getBlobForAsset(C_JPG);
        const blobType = blob.type;

        const ingredient: Ingredient = {
          title: 'C.jpg',
          format: blobType,
          instance_id: 'ingredient-instance-123'
        };

        await builder.addIngredientFromBlob(ingredient, blobType, blob);

        // Create C2PA archive from the builder
        const archive = await builder.toArchive();
        expect(archive).toBeDefined();
        expect(archive.byteLength).toBeGreaterThan(0);

        // Configure reader to skip verification for unsigned archive
        const readerContext: Settings = {
          verify: {
            verifyAfterReading: false
          }
        };

        // Read the C2PA archive with Reader using application/c2pa format
        const archiveBlob = new Blob([archive]);
        const reader = await c2pa.reader.fromBlob(
          'application/c2pa',
          archiveBlob,
          readerContext
        );

        expect(reader).not.toBeNull();
        expect(reader).toBeDefined();

        // Verify we can read the manifest from the archive
        const manifestStore = await reader!.manifestStore();
        expect(manifestStore).toBeDefined();
        expect(manifestStore.manifests).toBeDefined();

        const activeManifest = await reader!.activeManifest();

        // Verify the manifest contains our data
        expect(activeManifest.title).toEqual(manifestDefinition.title);
        expect(activeManifest.claim_generator_info).toMatchObject(
          manifestDefinition.claim_generator_info!
        );

        const activeManifestLabel = manifestStore.active_manifest;
        expect(activeManifestLabel).toBeDefined();
      });
    });
  });

  describe('methods', () => {
    describe('addAction', () => {
      test('should add the provided actions', async ({ c2pa }) => {
        const builder = await c2pa.builder.new();

        await builder.addAction({
          action: 'c2pa.opened'
        });

        await builder.addAction({
          action: 'c2pa.edited'
        });

        const definition = await builder.getDefinition();

        expect(definition).toEqual({
          assertions: [
            {
              data: {
                actions: [
                  {
                    action: 'c2pa.opened'
                  },
                  {
                    action: 'c2pa.edited'
                  }
                ]
              },
              label: 'c2pa.actions.v2'
            }
          ],
          claim_generator_info: [],
          format: '',
          ingredients: [],
          instance_id: ''
        });
      });
    });

    describe('addIngredient', () => {
      test('should add the provided ingredient', async ({ c2pa }) => {
        const builder = await c2pa.builder.new();

        const ingredient: Ingredient = {
          title: 'source-image.jpg',
          format: 'image/jpeg',
          instance_id: 'ingredient-instance-123',
          document_id: 'ingredient-doc-456'
        };

        await builder.addIngredient(ingredient);

        const definition = await builder.getDefinition();

        expect(definition.ingredients).toHaveLength(1);
        expect(definition.ingredients?.[0]).toMatchObject({
          title: 'source-image.jpg',
          format: 'image/jpeg',
          instance_id: 'ingredient-instance-123',
          document_id: 'ingredient-doc-456'
        });
      });

      test('should add multiple ingredients', async ({ c2pa }) => {
        const builder = await c2pa.builder.new();

        const ingredient1: Ingredient = {
          title: 'source-image-1.jpg',
          format: 'image/jpeg',
          instance_id: 'ingredient-instance-1'
        };

        const ingredient2: Ingredient = {
          title: 'source-image-2.jpg',
          format: 'image/jpeg',
          instance_id: 'ingredient-instance-2'
        };

        await builder.addIngredient(ingredient1);
        await builder.addIngredient(ingredient2);

        const definition = await builder.getDefinition();

        expect(definition.ingredients).toHaveLength(2);
        expect(definition.ingredients?.[0]).toMatchObject({
          title: 'source-image-1.jpg',
          format: 'image/jpeg',
          instance_id: 'ingredient-instance-1'
        });
        expect(definition.ingredients?.[1]).toMatchObject({
          title: 'source-image-2.jpg',
          format: 'image/jpeg',
          instance_id: 'ingredient-instance-2'
        });
      });

      test('should add ingredient from blob and archive for cloud-only file', async ({
        c2pa
      }) => {
        const blob = await getBlobForAsset(PirateShip_cloud);

        const builder = await c2pa.builder.new();

        const ingredient: Ingredient = {
          relationship: 'parentOf',
          title: 'PirateShip_cloud',
          format: blob.type
        };

        // addIngredientFromBlob can fetch remote manifests,
        await builder.addIngredientFromBlob(ingredient, blob.type, blob);

        // Verify the remote manifest was fetched: the ingredient should have
        // both activeManifest and validationResults present.
        const definition = await builder.getDefinition();
        expect(definition.ingredients).toHaveLength(1);
        const addedIngredient = definition.ingredients![0];
        expect(addedIngredient.active_manifest).toBeDefined();
        expect(addedIngredient.validation_results).toBeDefined();
      });

      test('should add ingredient with custom metadata', async ({ c2pa }) => {
        const builder = await c2pa.builder.new();

        const ingredient: Ingredient = {
          title: 'source-image.jpg',
          format: 'image/jpeg',
          instance_id: 'ingredient-instance-123',
          document_id: 'ingredient-doc-456',
          metadata: {
            customString: 'my custom value',
            customNumber: 42,
            customBool: true,
            customObject: {
              nested: 'value',
              count: 123
            },
            customArray: ['item1', 'item2', 'item3']
          }
        };

        await builder.addIngredient(ingredient);

        const definition = await builder.getDefinition();

        expect(definition.ingredients).toHaveLength(1);
        expect(definition.ingredients?.[0]).toMatchObject(ingredient);
      });
    });

    describe('sign', () => {
      test('should preserve sensitivity label order and produce a valid BMFF hash', async ({
        c2pa
      }) => {
        const builder = await c2pa.builder.fromDefinition({
          claim_generator_info: [
            {
              name: 'c2pa-web-test',
              version: '1.0.0'
            }
          ],
          title: 'sensitivity-label.mp4',
          format: 'video/mp4',
          instance_id: 'xmp:iid:sensitivity-label-test',
          assertions: [],
          ingredients: []
        });
        const signer = await createTestSigner();
        const source = new Blob([makeSensitivityLabelMp4()], {
          type: 'video/mp4'
        });

        const signedBytes = await builder.sign(signer, source.type, source);
        const boxes = readTopLevelBoxes(signedBytes);

        expect(boxes.slice(0, 3).map(box => [box.type, box.uuid])).toEqual([
          ['ftyp', undefined],
          ['uuid', SENSITIVITY_LABEL_UUID],
          ['uuid', C2PA_UUID]
        ]);
        expect(new TextDecoder().decode(boxes[1].payload)).toBe(
          SENSITIVITY_LABEL_XML
        );

        const reader = await c2pa.reader.fromBlob(
          source.type,
          new Blob([signedBytes], { type: source.type })
        );
        expect(reader).not.toBeNull();

        const manifestStore = await reader!.manifestStore();
        const successCodes =
          manifestStore.validation_results?.activeManifest?.success.map(
            result => result.code
          );

        expect(successCodes).toContain('claimSignature.validated');
        expect(successCodes).toContain('assertion.bmffHash.match');
      });
    });
  });
});
