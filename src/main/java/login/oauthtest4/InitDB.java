package login.oauthtest4;

import javax.persistence.EntityManager;
import login.oauthtest4.domain.user.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
@RequiredArgsConstructor
@Slf4j
public class InitDB implements CommandLineRunner {

    private final InitService initService;


    @Override
    public void run(String... args) {
        initService.initializeData();
    }

    @Component
    @RequiredArgsConstructor
    static class InitService {

        private final EntityManager em;

        @Transactional
        public void initializeData() {
            User user1 = User.builder()
                .email("1234")
//                .age(10)
                .build();

            em.persist(user1);
        }
    }


}