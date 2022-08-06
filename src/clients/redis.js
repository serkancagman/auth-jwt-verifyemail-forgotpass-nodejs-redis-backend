import Redis from 'ioredis';

const redis = new Redis({
    port: 11180,
    host: "redis-11180.c55.eu-central-1-1.ec2.cloud.redislabs.com",
    password: "DIoSX0kZLMPBiMFTAaOiLPHUZt32XAXV",
});

export default redis;