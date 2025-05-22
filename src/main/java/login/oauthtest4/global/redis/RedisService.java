package login.oauthtest4.global.redis;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.HashOperations;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class RedisService {

    private final RedisTemplate<String, Object> redisTemplate;
    private final Duration refreshTokenDuration = Duration.ofDays(7);

    //refreshToken redis 저장
    public void setRefreshTokenValues(String key, String data) {
        ValueOperations<String, Object> values = redisTemplate.opsForValue();
        values.set(key, data, refreshTokenDuration);
    }

    public void setValues(String key, String data, Duration duration) {
        ValueOperations<String, Object> values = redisTemplate.opsForValue();
        values.set(key, data, duration);
    }

    public void setTossValues(String key, Integer data, Duration duration) {
        ValueOperations<String, Object> values = redisTemplate.opsForValue();
        values.set(key, data, duration);
    }

    @Transactional(readOnly = true)
    public String getValues(String key) {
        ValueOperations<String, Object> values = redisTemplate.opsForValue();
//        if (values.get(key) == null) {
//            return "false";
//        }
//        return (String) values.get(key);
        Object value = values.get(key);
        return value != null ? (String) value : null;
    }

    @Transactional(readOnly = true)
    public Integer getTossValuesAsInteger(String orderId) {
        ValueOperations<String, Object> values = redisTemplate.opsForValue();
        Object value = values.get(orderId);
        if (value instanceof Integer) {
            return (Integer) value;
        }
        log.warn("Retrieved value for key {} is not an Integer: {}", orderId, value);
        return null;
    }

    public boolean setTossValuesIfAbsent(String orderId, Integer amount, Duration duration) {
        if (orderId == null || orderId.isEmpty()) {
            throw new IllegalArgumentException("키는 null이거나 빈 문자열일 수 없습니다.");
        }
        if (amount == null) {
            throw new IllegalArgumentException("데이터는 null일 수 없습니다.");
        }
        if (duration == null || duration.isNegative()) {
            throw new IllegalArgumentException("유효 기간은 null이 아니고, 음수가 아니어야 합니다.");
        }

        ValueOperations<String, Object> values = redisTemplate.opsForValue();
        Boolean success = values.setIfAbsent(orderId, amount, duration);
        return success != null && success;
    }

    public void deleteValues(String key) {
        redisTemplate.delete(key);
    }

    public void expireValues(String key, int timeout) {
        redisTemplate.expire(key, timeout, TimeUnit.MILLISECONDS);
    }

    public void setHashOps(String key, Map<String, String> data) {
        HashOperations<String, Object, Object> values = redisTemplate.opsForHash();
        values.putAll(key, data);
    }

    @Transactional(readOnly = true)
    public String getHashOps(String key, String hashKey) {
        HashOperations<String, Object, Object> values = redisTemplate.opsForHash();
        return Boolean.TRUE.equals(values.hasKey(key, hashKey)) ? (String) redisTemplate.opsForHash().get(key, hashKey) : "";
    }

    public void deleteHashOps(String key, String hashKey) {
        HashOperations<String, Object, Object> values = redisTemplate.opsForHash();
        values.delete(key, hashKey);
    }

    public boolean checkExistsValue(String value) {
        return !value.equals("false");
    }
}