/* tslint:disable:no-unused-variable */

import { TestBed, waitForAsync, inject } from '@angular/core/testing';
import { DocumentsService } from './documents.service';

describe('Service: Documents', () => {
  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [DocumentsService]
    });
  });

  it('should ...', inject([DocumentsService], (service: DocumentsService) => {
    expect(service).toBeTruthy();
  }));
});
