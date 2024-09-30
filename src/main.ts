import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { json } from 'express';
import {
  UnprocessableEntityException,
  ValidationError,
  ValidationPipe,
} from '@nestjs/common';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import * as cookieParser from 'cookie-parser';

// Constants
export const IS_PRODUCTION = process.env.NODE_ENV === 'production';
const SERVER_PORT = process.env.SERVER_PORT || 8000;

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Add security headers
  app.use(helmet());

  // Add rate limiting
  app.use(
    rateLimit({
      windowMs: 15 * 60 * 1000, // 15 minutes
      limit: 100, // limit each IP to 100 requests per window
    }),
  );

  // Body parser limit
  app.use(json({ limit: '10kb' }));

  // Cookie parser
  app.use(cookieParser());

  // Validate incoming requests. This will apply to all routes
  // Remove the whitelist option to allow all properties to be passed through
  // Remove the transform option to disable automatic type conversion
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      transform: true,
      exceptionFactory: (validationErrors: ValidationError[] = []) => {
        const errors = [];

        const getValidationErrorsRecursively = (
          validationErrors: ValidationError[],
          parentProperty = '',
        ) => {
          validationErrors.forEach((error) => {
            const propertyPath = parentProperty
              ? [parentProperty, error.property].join('.')
              : error.property;

            if (error.constraints)
              errors.push({
                property: propertyPath,
                errors: Object.values(error.constraints),
              });

            if (error.children?.length)
              getValidationErrorsRecursively(error.children, propertyPath);
          });
        };
        getValidationErrorsRecursively(validationErrors);

        return new UnprocessableEntityException({
          message: 'Validation Error',
          errors: errors,
        });
      },
    }),
  );

  // Swagger API documentation
  const config = new DocumentBuilder()
    .setTitle('Alpha API')
    .setDescription('The Alpha API description')
    .setVersion('0.1')
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('docs', app, document);

  await app.listen(SERVER_PORT);
}

bootstrap();
