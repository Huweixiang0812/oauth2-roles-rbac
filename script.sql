
SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;
-- ----------------------------
-- Table structure for role
-- ----------------------------
DROP TABLE IF EXISTS `role`;
CREATE TABLE `role` (
                        `role_id` int NOT NULL AUTO_INCREMENT,
                        `role_name` varchar(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_c
                            i NOT NULL,
                        PRIMARY KEY (`role_id`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci ROW
_FORMAT = Dynamic;

-- ----------------------------
-- Records of role
-- ----------------------------
INSERT INTO `role` VALUES (1, 'USER');
INSERT INTO `role` VALUES (2, 'ADMIN');

-- ----------------------------
-- Table structure for role_url_mapping
-- ----------------------------
DROP TABLE IF EXISTS `role_url_mapping`;
CREATE TABLE `role_url_mapping` (
                                    `ru_id` int NOT NULL AUTO_INCREMENT,
                                    `role_id` int NOT NULL,
                                    `url_id` int NOT NULL,
                                    PRIMARY KEY (`ru_id`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci ROW
_FORMAT = Dynamic;


-- ----------------------------
-- Records of role_url_mapping
-- ----------------------------
INSERT INTO `role_url_mapping` VALUES (1, 1, 1);
INSERT INTO `role_url_mapping` VALUES (2, 1, 2);
INSERT INTO `role_url_mapping` VALUES (3, 2, 3);
INSERT INTO `role_url_mapping` VALUES (4, 1, 4);
INSERT INTO `role_url_mapping` VALUES (5, 2, 4);


DROP TABLE IF EXISTS `url_resource`;
CREATE TABLE `url_resource` (
                                `url_id` int NOT NULL AUTO_INCREMENT,
                                `url_pattern` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai
                                    _ci NOT NULL,
                                `namespace` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_c
                                    i NOT NULL,
                                PRIMARY KEY (`url_id`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci ROW
_FORMAT = Dynamic;



-- ----------------------------
-- Records of url_resource
-- ----------------------------
INSERT INTO `url_resource` VALUES (1, '/products', 'res-sample');
INSERT INTO `url_resource` VALUES (2, '/user/*', 'res-sample');
INSERT INTO `url_resource` VALUES (3, '/admin/*', 'res-sample');
INSERT INTO `url_resource` VALUES (4, '/sso/user', 'res-sample');
SET FOREIGN_KEY_CHECKS = 1;