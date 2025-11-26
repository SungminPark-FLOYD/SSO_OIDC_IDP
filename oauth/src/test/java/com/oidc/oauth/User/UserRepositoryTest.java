package com.oidc.oauth.User;

import com.oidc.oauth.api.user.User;
import com.oidc.oauth.api.user.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
public class UserRepositoryTest {
    @Autowired
    UserRepository repo;

    @Test
    void testSave() {
        User user = new User();
        //user.setName("홍길동");
        repo.save(user);
    }
}
