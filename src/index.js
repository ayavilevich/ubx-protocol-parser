/* eslint-disable no-mixed-operators */
/* eslint no-bitwise: "off" */
/* eslint no-restricted-syntax: "off" */
import Debug from 'debug';
import { Transform } from 'stream';
import { packetClassIdToLength } from './ubx';

const debug = Debug('ubx:protocol:parser');

const PACKET_SYNC_1 = 0;
const PACKET_SYNC_2 = 1;
const PACKET_CLASS = 2;
const PACKET_ID = 3;
const PACKET_LENGTH = 4;
const PACKET_LENGTH_2 = 5;
const PACKET_PAYLOAD = 6;
const PACKET_CHECKSUM = 7;

/*
Limit max payload size to prevent a corrupt length from messing with data.
In case of an invalid length, this state machine will not "go back" and data will be lost. In any case, a delay is not desired.
Mind that some messages have variable length so set the max correctly depending on the messages you have enabled.
You can override the default using options.maxPacketPayloadLength
*/
const DEFAULT_MAX_PACKET_PAYLOAD_LENGTH = 300; // cap max packet size, proper max will depend on the type of messages the ubx is sending

const packetTemplate = {
  class: 0,
  id: 0,
  length: 0,
  payload: null,
  checksum: 0,
};

function calcCheckSum(messageClass, id, length, payload) {
  let buffer = Buffer.alloc(4);
  buffer.writeUInt8(messageClass, 0);
  buffer.writeUInt8(id, 1);
  buffer.writeUInt16LE(length, 2);
  buffer = Buffer.concat([buffer, payload]);

  let a = 0;
  let b = 0;

  for (let i = 0; i < buffer.length; i += 1) {
    [a] = new Uint8Array([(a + buffer[i])]);
    [b] = new Uint8Array([(b + a)]);
  }

  return (b << 8) | a;
}

export default class UBXProtocolParser extends Transform {
  constructor(options) {
    super({
      ...options,
      objectMode: true,
    });

    // this.buffer = Buffer.alloc(0); // this seems unnecessary and incorrect
    this.packet = { ...packetTemplate };
    this.payloadPosition = 0;
    this.packetStartFound = false;
    this.packetState = PACKET_SYNC_1;
    this.streamIndex = 0;
    // max payload size to allow. pass 0 to disable this check.
    this.maxPacketPayloadLength = typeof options === 'object' && typeof options.maxPacketPayloadLength === 'number' ? options.maxPacketPayloadLength : DEFAULT_MAX_PACKET_PAYLOAD_LENGTH;
  }

  // eslint-disable-next-line no-underscore-dangle
  _transform(chunk, encoding, cb) {
    // const data = Buffer.concat([this.buffer, chunk]);
    const data = chunk;

    for (const [i, byte] of data.entries()) {
      // debug(`Incoming byte "${byte}", 0x${byte.toString(16)} received at state "${this.packetState},${this.packetStartFound}"`);
      // debug(`payload.len: ${this.packet.length}, payloadPosition: ${this.payloadPosition}, streamIndex: ${this.streamIndex}`);
      if (this.packetStartFound) {
        switch (this.packetState) {
          case PACKET_SYNC_1:
            if (byte === 0x62) {
              this.packetState = PACKET_SYNC_2;
            } else if (byte === 0xB5) { // 0xB5 after another 0xB5 (happens in the stream)
              // remain in same state
            } else {
              debug(`Unknown byte "${byte}", 0x${byte.toString(16)} received at state "${this.packetState},${this.packetStartFound}"`);
              this.resetState();
            }
            break;

          case PACKET_SYNC_2:
            this.packet.class = byte;
            this.packetState = PACKET_CLASS;
            break;

          case PACKET_CLASS:
            this.packet.id = byte;
            this.packetState = PACKET_ID;
            break;

          case PACKET_ID:
            this.packet.length = byte;
            this.packetState = PACKET_LENGTH;
            break;

          case PACKET_LENGTH: {
            this.packet.length = this.packet.length + byte * 2 ** 8;
            // verify length for class/id
            const packetType = `${this.packet.class}_${this.packet.id}`;
            if (this.maxPacketPayloadLength && this.packet.length > this.maxPacketPayloadLength) {
              debug(`Payload length ${this.packet.length} larger than allowed max length ${this.maxPacketPayloadLength}`);
              this.emit('payload_too_large', { packet: this.packet, maxPacketPayloadLength: this.maxPacketPayloadLength });
              this.resetState();
            } else if (this.packet.length === 0) { // poll packet
              this.packetState = PACKET_PAYLOAD; // packet with no payload, go straight to checksum state
              this.packet.payload = Buffer.alloc(0);
            } else if (typeof packetClassIdToLength[packetType] === 'number' && this.packet.length !== packetClassIdToLength[packetType]) {
              debug(`Payload length ${this.packet.length} wrong for packet class/id ${packetClassIdToLength[packetType]}, ${packetType}`);
              this.emit('wrong_payload_length', { packet: this.packet, expectedPayloadLength: packetClassIdToLength[packetType] });
              this.resetState();
            } else { // normal case
              this.packetState = PACKET_LENGTH_2;
            }
            break;
          }
          case PACKET_LENGTH_2:
            if (this.packet.payload === null) {
              this.packet.payload = Buffer.alloc(this.packet.length);
              this.payloadPosition = 0;
            }

            this.packet.payload[this.payloadPosition] = byte;
            this.payloadPosition += 1;

            if (this.payloadPosition >= this.packet.length) {
              this.packetState = PACKET_PAYLOAD;
            }

            break;

          case PACKET_PAYLOAD:
            this.packet.checksum = byte;
            this.packetState = PACKET_CHECKSUM;
            break;

          case PACKET_CHECKSUM: {
            this.packet.checksum = this.packet.checksum + byte * 2 ** 8;

            const checksum = calcCheckSum(
              this.packet.class,
              this.packet.id,
              this.packet.length,
              this.packet.payload,
            );

            if (checksum === this.packet.checksum) {
              if (this.packet.length > 0) { // if not polling but actual data
                this.push({
                  messageClass: this.packet.class,
                  messageId: this.packet.id,
                  payload: this.packet.payload,
                });
              } else {
                this.emit('polling_message', { packet: this.packet });
              }
            } else {
              debug(`Checksum "${checksum}" doesn't match received CheckSum "${this.packet.checksum}"`);
              // emit an event about the failed checksum
              this.emit('failed_checksum', { packet: this.packet, checksum });
            }

            this.resetState();
            // this.buffer = data.slice(i + 1);
            break;
          }
          default:
            debug(`Should never reach this packetState "${this.packetState}`);
        }
      } else if (byte === 0xB5) {
        this.packetStartFound = true;
        this.packetState = PACKET_SYNC_1;
      } else {
        debug(`Unknown byte "${byte}", 0x${byte.toString(16)} received at state "${this.packetState},${this.packetStartFound}"`);
      }
      this.streamIndex += 1;
    }

    cb();
  }

  resetState() {
    this.packetState = PACKET_SYNC_1;
    this.packet = { ...packetTemplate };
    this.payloadPosition = 0;
    this.packetStartFound = false;
    // this.buffer = Buffer.alloc(0);
  }

  // eslint-disable-next-line no-underscore-dangle
  _flush(cb) {
    this.resetState();
    cb();
  }
}
